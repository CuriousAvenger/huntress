"""Typed verification failures.

Errors are reserved for programming/integrity problems and forbidden review
transitions. A candidate that fails its deterministic gates is a normal
``ValidationOutcome`` with a non-passing status, not an exception.
"""

from __future__ import annotations


class VerificationError(Exception):
    """Base class for verification-layer failures."""


class ValidationConflict(VerificationError):
    """A caller supplied an identifier that already exists."""


class ReviewDenied(VerificationError):
    """A human-review transition is not allowed for this finding."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason
