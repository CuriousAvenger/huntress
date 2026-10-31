"""Typed reasoning-layer failures."""

from __future__ import annotations

from huntress_contracts import ModelCallStatus


class ReasoningError(Exception):
    """Base class for reasoning/context failures."""


class UnknownProvider(ReasoningError):
    """The configured model provider is not supported."""


class MissingCredential(ReasoningError):
    """A required provider credential is not present in the environment."""


class PromptVersionMismatch(ReasoningError):
    """A context packet was compiled for a different prompt/schema version."""


class TaskMismatch(ReasoningError):
    """A packet was compiled for a different reasoning checkpoint."""


class ContextError(ReasoningError):
    """A context packet cannot be compiled safely from the supplied state."""


class ContextTooLarge(ContextError):
    """The compiled packet exceeds the configured character budget."""


class RuntimeInvocationError(ReasoningError):
    """A model invocation failed in a way that must be recorded, not retried blindly."""

    def __init__(
        self,
        message: str,
        *,
        status: ModelCallStatus = ModelCallStatus.PROVIDER_ERROR,
        input_tokens: int = 0,
        output_tokens: int = 0,
        stop_reason: str = "",
        error_code: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.input_tokens = max(0, input_tokens)
        self.output_tokens = max(0, output_tokens)
        self.stop_reason = stop_reason
        self.error_code = error_code
