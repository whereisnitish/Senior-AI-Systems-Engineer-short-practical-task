"""Domain errors mapped to consistent HTTP error responses.

Messages must never contain secret values; callers pass field names, not inputs.
"""

from __future__ import annotations

from typing import Any


class DomainError(Exception):
    status_code = 400
    code = "bad_request"

    def __init__(self, message: str, *, details: Any = None, code: str | None = None):
        super().__init__(message)
        self.message = message
        self.details = details
        if code:
            self.code = code


class NotFound(DomainError):
    status_code = 404
    code = "not_found"


class Conflict(DomainError):
    status_code = 409
    code = "conflict"


class InvalidTransition(Conflict):
    code = "invalid_transition"


class ValidationFailed(DomainError):
    status_code = 422
    code = "validation_failed"


class SecretMaterialRejected(ValidationFailed):
    code = "secret_material_rejected"


class AuthenticationRequired(DomainError):
    status_code = 401
    code = "unauthenticated"


class PermissionDenied(DomainError):
    status_code = 403
    code = "forbidden"


class TooManyAttempts(DomainError):
    status_code = 429
    code = "too_many_attempts"

    def __init__(self, message: str, *, retry_after: int):
        super().__init__(message)
        self.retry_after = retry_after


class IntegrationUnavailable(DomainError):
    status_code = 503
    code = "integration_unavailable"


class DestinationNotApproved(DomainError):
    status_code = 422
    code = "destination_not_approved"


class SessionPaused(Conflict):
    code = "session_paused_for_human_review"
