"""Shared exception types for validation and future protocol adapters."""


class PPMLHealthcareError(Exception):
    """Base exception for this package."""


class SchemaValidationError(PPMLHealthcareError, ValueError):
    """Raised when untrusted data does not satisfy a typed schema."""


class AdapterNotImplementedError(PPMLHealthcareError, NotImplementedError):
    """Raised by interfaces that have no concrete implementation yet."""


class ProtocolRejectedError(PPMLHealthcareError):
    """Raised when a future protocol implementation rejects a message."""
