"""
Metadata Collector for py-libp2p Privacy Analysis

This module hooks into py-libp2p's event system to collect privacy-relevant metadata
without disrupting core functionality.

Key instrumentation points:
- Connection establishment/teardown
- Peer discovery events
- Protocol negotiation
- Stream creation/closure
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, TYPE_CHECKING
from collections import defaultdict

from multiaddr import Multiaddr
from libp2p.peer.id import ID as PeerID
from libp2p.abc import INetConn, INetStream, INetwork, INotifee

if TYPE_CHECKING:
    from typing import Any


@dataclass
class ConnectionMetadata:
    """
    Metadata about a single connection.
    
    This data structure is designed to be ZK-ready for future proof generation.
    """
    peer_id: str
    multiaddr: str
    direction: str  # "inbound" or "outbound"
    timestamp_start: float
    timestamp_end: Optional[float] = None
    protocols: List[str] = field(default_factory=list)
    stream_count: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    
    # Privacy-relevant fields
    connection_duration: Optional[float] = None
    is_direct: bool = True
    transport_type: Optional[str] = None
    
    def finalize(self):
        """Calculate derived fields when connection ends."""
        if self.timestamp_end:
            self.connection_duration = self.timestamp_end - self.timestamp_start
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "peer_id": self.peer_id,
            "multiaddr": self.multiaddr,
            "direction": self.direction,
            "timestamp_start": self.timestamp_start,
            "timestamp_end": self.timestamp_end,
            "protocols": self.protocols,
            "stream_count": self.stream_count,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "connection_duration": self.connection_duration,
            "is_direct": self.is_direct,
            "transport_type": self.transport_type,
        }


@dataclass
class PeerMetadata:
    """
    Aggregated metadata about a peer across multiple connections.
    """
    peer_id: str
    first_seen: float
    last_seen: float
    connection_count: int = 0
    total_duration: float = 0.0
    multiaddrs: Set[str] = field(default_factory=set)
    protocols: Set[str] = field(default_factory=set)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "peer_id": self.peer_id,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "connection_count": self.connection_count,
            "total_duration": self.total_duration,
            "multiaddrs": list(self.multiaddrs),
            "protocols": list(self.protocols),
        }


class PrivacyNotifee(INotifee):
    """
    Network notifee implementation to capture privacy-relevant events.
    
    This class implements the INotifee interface and forwards events
    to the MetadataCollector for processing.
    """
    
    def __init__(self, collector: 'MetadataCollector'):
        """
        Initialize the notifee.
        
        Args:
            collector: The MetadataCollector instance to forward events to
        """
        self.collector = collector
    
    async def opened_stream(self, network: INetwork, stream: INetStream) -> None:
        """Called when a new stream is opened."""
        peer_id = stream.muxed_conn.peer_id
        self.collector.on_stream_opened(peer_id)
    
    async def closed_stream(self, network: INetwork, stream: INetStream) -> None:
        """Called when a stream is closed."""
        # Stream closed event
        pass
    
    async def connected(self, network: INetwork, conn: INetConn) -> None:
        """Called when a new connection is established."""
        try:
            # Get peer_id from muxed connection
            peer_id = conn.muxed_conn.peer_id
            
            # Get multiaddr from the connection itself (or from raw connection)
            if hasattr(conn, 'multiaddr') and conn.multiaddr:
                multiaddr = conn.multiaddr
            elif hasattr(conn, 'raw_conn') and hasattr(conn.raw_conn, 'multiaddr'):
                multiaddr = conn.raw_conn.multiaddr
            else:
                # Avoid peerstore lookups to prevent noisy warnings.
                multiaddr = None
            
            # Determine direction based on whether we initiated the connection
            direction = "outbound" if hasattr(conn, 'initiator') and conn.initiator else "inbound"
            
            self.collector.on_connection_opened(peer_id, multiaddr, direction)
            print(f"[PrivacyNotifee] Connected: {peer_id} via {multiaddr}")
        except Exception as e:
            print(f"[PrivacyNotifee] Error in connected(): {e}")
            import traceback
            traceback.print_exc()
    
    async def disconnected(self, network: INetwork, conn: INetConn) -> None:
        """Called when a connection is closed."""
        try:
            peer_id = conn.muxed_conn.peer_id if hasattr(conn, 'muxed_conn') and conn.muxed_conn else None
            
            # Get multiaddr from the connection itself
            multiaddr = None
            if hasattr(conn, 'multiaddr') and conn.multiaddr:
                multiaddr = conn.multiaddr
            elif hasattr(conn, 'raw_conn') and hasattr(conn.raw_conn, 'multiaddr'):
                multiaddr = conn.raw_conn.multiaddr
            else:
                multiaddr = None
            
            if peer_id and multiaddr:
                self.collector.on_connection_closed(peer_id, multiaddr)
                print(f"[PrivacyNotifee] Disconnected: {peer_id}")
        except Exception as e:
            print(f"[PrivacyNotifee] Error in disconnected(): {e}")
    
    async def listen(self, network: INetwork, multiaddr: Multiaddr) -> None:
        """Called when the node starts listening on a new multiaddr."""
        pass
    
    async def listen_close(self, network: INetwork, multiaddr: Multiaddr) -> None:
        """Called when the node stops listening on a multiaddr."""
        pass


class MetadataCollector:
    """
    Collects privacy-relevant metadata from py-libp2p nodes.
    
    This collector hooks into the libp2p event system to monitor:
    - Connection lifecycle events
    - Peer discovery
    - Protocol negotiations
    - Stream operations
    
    The collected data is used for privacy analysis and (future) ZK proof generation.
    """
    
    def __init__(self, libp2p_host=None):
        """
        Initialize the metadata collector.
        
        Args:
            libp2p_host: Optional py-libp2p host instance to monitor
        """
        self.host = libp2p_host
        
        # Storage for collected metadata
        self.connections: Dict[str, ConnectionMetadata] = {}
        self.peers: Dict[str, PeerMetadata] = {}
        self.connection_history: List[ConnectionMetadata] = []
        
        # Timing data for correlation analysis
        self.connection_times: List[float] = []
        self.disconnection_times: List[float] = []
        
        # Protocol usage tracking
        self.protocol_usage: Dict[str, int] = defaultdict(int)
        
        # Session tracking
        self.active_sessions: Set[str] = set()
        
        # Statistics
        self.total_connections = 0
        self.total_disconnections = 0

        # Warnings
        self.warnings: List[Dict[str, str]] = []
        self._warned_missing_addrs: Set[str] = set()
        
        # Setup hooks if host provided
        if self.host:
            self.setup_hooks()
    
    def setup_hooks(self):
        """
        Set up event hooks into py-libp2p.
        
        This registers a notifee with the libp2p network to receive
        connection and stream events.
        """
        if not self.host:
            return
        
        # Create and register our notifee
        self.notifee = PrivacyNotifee(self)
        network = self.host.get_network()
        network.register_notifee(self.notifee)
        
        print(f"✓ Privacy notifee registered with {network}")
    
    def on_connection_opened(self, peer_id: PeerID, multiaddr: Multiaddr, direction: str):
        """
        Called when a new connection is opened.
        
        Args:
            peer_id: The peer ID of the remote peer
            multiaddr: The multiaddr of the connection
            direction: "inbound" or "outbound"
        """
        peer_id_str = str(peer_id)
        if multiaddr is None:
            if peer_id_str not in self._warned_missing_addrs:
                self._warned_missing_addrs.add(peer_id_str)
                self.warnings.append(
                    {
                        "message": f"Peerstore missing addrs for peer {peer_id_str} (non-fatal).",
                        "impact": "Address attribution in report may be incomplete.",
                        "peer_id": peer_id_str,
                    }
                )
            multiaddr_str = "unknown"
        else:
            multiaddr_str = str(multiaddr)
        connection_id = f"{peer_id_str}_{time.time()}"
        
        # Create connection metadata
        metadata = ConnectionMetadata(
            peer_id=peer_id_str,
            multiaddr=multiaddr_str,
            direction=direction,
            timestamp_start=time.time(),
            transport_type=self._extract_transport_type(multiaddr_str)
        )
        
        self.connections[connection_id] = metadata
        self.connection_times.append(metadata.timestamp_start)
        self.total_connections += 1
        self.active_sessions.add(connection_id)
        
        # Update peer metadata
        self._update_peer_metadata(peer_id_str, multiaddr_str)
    
    def on_connection_closed(self, peer_id: PeerID, multiaddr: Multiaddr):
        """
        Called when a connection is closed.
        
        Args:
            peer_id: The peer ID of the remote peer
            multiaddr: The multiaddr of the connection
        """
        peer_id_str = str(peer_id)
        current_time = time.time()
        
        # Find and finalize the connection
        for conn_id, metadata in self.connections.items():
            if metadata.peer_id == peer_id_str and metadata.timestamp_end is None:
                metadata.timestamp_end = current_time
                metadata.finalize()
                
                # Move to history
                self.connection_history.append(metadata)
                self.disconnection_times.append(current_time)
                self.total_disconnections += 1
                self.active_sessions.discard(conn_id)
                
                # Update peer metadata
                if peer_id_str in self.peers:
                    self.peers[peer_id_str].last_seen = current_time
                    if metadata.connection_duration:
                        self.peers[peer_id_str].total_duration += metadata.connection_duration
                
                break
    
    def on_protocol_negotiated(self, peer_id: PeerID, protocol: str):
        """
        Called when a protocol is successfully negotiated.
        
        Args:
            peer_id: The peer ID of the remote peer
            protocol: The protocol identifier
        """
        peer_id_str = str(peer_id)
        
        # Track protocol usage
        self.protocol_usage[protocol] += 1
        
        # Update connection metadata
        for metadata in self.connections.values():
            if metadata.peer_id == peer_id_str and metadata.timestamp_end is None:
                if protocol not in metadata.protocols:
                    metadata.protocols.append(protocol)
        
        # Update peer metadata
        if peer_id_str in self.peers:
            self.peers[peer_id_str].protocols.add(protocol)
    
    def on_stream_opened(self, peer_id: PeerID):
        """
        Called when a new stream is opened.
        
        Args:
            peer_id: The peer ID of the remote peer
        """
        peer_id_str = str(peer_id)
        
        # Update stream count in active connections
        for metadata in self.connections.values():
            if metadata.peer_id == peer_id_str and metadata.timestamp_end is None:
                metadata.stream_count += 1
    
    def record_data_transfer(self, peer_id: PeerID, bytes_sent: int, bytes_received: int):
        """
        Record data transfer statistics.
        
        Args:
            peer_id: The peer ID of the remote peer
            bytes_sent: Number of bytes sent
            bytes_received: Number of bytes received
        """
        peer_id_str = str(peer_id)
        
        # Update active connections
        for metadata in self.connections.values():
            if metadata.peer_id == peer_id_str and metadata.timestamp_end is None:
                metadata.bytes_sent += bytes_sent
                metadata.bytes_received += bytes_received
    
    def _update_peer_metadata(self, peer_id: str, multiaddr: str):
        """Update aggregated peer metadata."""
        current_time = time.time()
        
        if peer_id not in self.peers:
            self.peers[peer_id] = PeerMetadata(
                peer_id=peer_id,
                first_seen=current_time,
                last_seen=current_time
            )
        
        peer = self.peers[peer_id]
        peer.connection_count += 1
        peer.last_seen = current_time
        peer.multiaddrs.add(multiaddr)
    
    def _extract_transport_type(self, multiaddr: str) -> str:
        """Extract transport type from multiaddr."""
        if "/tcp/" in multiaddr:
            return "tcp"
        elif "/quic/" in multiaddr or "/quic-v1/" in multiaddr:
            return "quic"
        elif "/ws/" in multiaddr or "/wss/" in multiaddr:
            return "websocket"
        else:
            return "unknown"
    
    def get_active_connections(self) -> List[ConnectionMetadata]:
        """Get all currently active connections."""
        return [
            conn for conn in self.connections.values()
            if conn.timestamp_end is None
        ]
    
    def get_connection_history(self, limit: Optional[int] = None) -> List[ConnectionMetadata]:
        """
        Get connection history.
        
        Args:
            limit: Optional limit on number of connections to return
        
        Returns:
            List of connection metadata, most recent first
        """
        history = sorted(
            self.connection_history,
            key=lambda x: x.timestamp_start,
            reverse=True
        )
        
        if limit:
            return history[:limit]
        return history
    
    def get_peer_metadata(self, peer_id: str) -> Optional[PeerMetadata]:
        """Get metadata for a specific peer."""
        return self.peers.get(peer_id)
    
    def get_all_peers(self) -> List[PeerMetadata]:
        """Get metadata for all known peers."""
        return list(self.peers.values())
    
    def get_statistics(self) -> dict:
        """Get overall statistics."""
        return {
            "total_connections": self.total_connections,
            "total_disconnections": self.total_disconnections,
            "active_connections": len(self.get_active_connections()),
            "unique_peers": len(self.peers),
            "protocols_used": len(self.protocol_usage),
            "total_connection_history": len(self.connection_history),
        }
    
    def export_data(self) -> dict:
        """
        Export all collected data for analysis.
        
        Returns:
            Dictionary containing all metadata in serializable format
        """
        return {
            "statistics": self.get_statistics(),
            "active_connections": [conn.to_dict() for conn in self.get_active_connections()],
            "connection_history": [conn.to_dict() for conn in self.connection_history],
            "peers": [peer.to_dict() for peer in self.peers.values()],
            "protocol_usage": dict(self.protocol_usage),
            "warnings": list(self.warnings),
            "connection_times": self.connection_times,
            "disconnection_times": self.disconnection_times,
        }

    def get_warnings(self) -> List[Dict[str, str]]:
        return list(self.warnings)
    
    def clear(self):
        """Clear all collected metadata."""
        self.connections.clear()
        self.peers.clear()
        self.connection_history.clear()
        self.connection_times.clear()
        self.disconnection_times.clear()
        self.protocol_usage.clear()
        self.active_sessions.clear()
        self.total_connections = 0
        self.total_disconnections = 0
