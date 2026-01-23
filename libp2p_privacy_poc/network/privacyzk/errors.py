"""Protocol error types."""


class ProtocolError(Exception):
    """Base error for privacy proof protocol issues."""


class SchemaError(ProtocolError):
    """Raised when a message fails schema validation."""


class SizeLimitError(ProtocolError):
    """Raised when a message exceeds configured size limits."""
