"""
⚠️ DRAFT — requires crypto review before production use

Custom exceptions for privacy protocol.

These exceptions provide structured error handling for cryptographic operations.
"""


class PrivacyProtocolError(Exception):
    """Base exception for privacy protocol errors."""

    pass


class ProofGenerationError(PrivacyProtocolError):
    """Error during proof generation."""

    pass


class ProofVerificationError(PrivacyProtocolError):
    """Error during proof verification."""

    pass


class ConfigurationError(PrivacyProtocolError):
    """Configuration error."""

    pass


class CryptographicError(PrivacyProtocolError):
    """Cryptographic operation error."""

    pass


class SecurityError(PrivacyProtocolError):
    """Security requirement violation."""

    pass
