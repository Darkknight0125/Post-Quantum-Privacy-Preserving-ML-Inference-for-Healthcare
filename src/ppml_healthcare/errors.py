"""Shared exception types for validation and future protocol adapters."""


class PPMLHealthcareError(Exception):
    """Base exception for this package."""


class SchemaValidationError(PPMLHealthcareError, ValueError):
    """Raised when untrusted data does not satisfy a typed schema."""


class AdapterNotImplementedError(PPMLHealthcareError, NotImplementedError):
    """Raised by interfaces that have no concrete implementation yet."""


class ProtocolRejectedError(PPMLHealthcareError):
    """Raised when a future protocol implementation rejects a message."""


class RegistryError(PPMLHealthcareError):
    """Base exception for membership and model registry operations."""


class RegistryConflictError(RegistryError):
    """Raised when an operation would silently replace registered state."""


class UnknownMemberError(RegistryError):
    """Raised when revoking or rotating an unregistered hospital key."""


class ModelArtifactMismatchError(RegistryError):
    """Raised when artifact bytes do not match a registered model digest."""
