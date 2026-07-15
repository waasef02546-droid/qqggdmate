"""Typed protocol errors."""


class PresagaError(Exception):
    """Base PRE-SAGA error."""


class PolicyDenied(PresagaError):
    """Raised when Data Sharing Policy denies a request."""


class TokenInvalid(PresagaError):
    """Raised when a data token is invalid."""


class StoreError(PresagaError):
    """Raised for encrypted store errors."""
