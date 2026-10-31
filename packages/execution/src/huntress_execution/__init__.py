"""Execution service, fixed profile registry, Exegol MCP adapter, fake backend."""

from .builtin import BuiltinBackend, BuiltinRunner
from .errors import (
    BackendContractError,
    BackendUnavailable,
    ExecutionDenied,
    ExecutionError,
    IdempotentReplay,
    ProfileUnknown,
)
from .exegol import (
    DEFAULT_EXEGOL_URL,
    EXECUTE_TOOL,
    ExegolAdapter,
    ExegolProbe,
    detect_exegol,
)
from .fake import (
    FakeExecutionBackend,
    FakeResponse,
    InMemoryAttemptStore,
    InMemoryExecutionLedger,
    InMemoryFindingStore,
)
from .models import (
    AttemptStore,
    AuditSink,
    BackendContext,
    BackendOutput,
    ExecutionBackendPort,
    ExecutionLedger,
    ExecutionOutcome,
    FindingStore,
)
from .profiles import (
    ALL_PROFILE_IDS,
    ALL_PROFILES,
    DEFAULT_PROFILE_REGISTRY,
    EXEGOL_PROFILES,
    ProfileRegistry,
    all_profiles,
    build_command,
    profile,
    resolve_argv,
    validate_argv_template,
)
from .service import ExecutionService

__version__ = "0.1.0"

__all__ = [
    "ALL_PROFILES",
    "ALL_PROFILE_IDS",
    "DEFAULT_EXEGOL_URL",
    "DEFAULT_PROFILE_REGISTRY",
    "EXECUTE_TOOL",
    "EXEGOL_PROFILES",
    "AttemptStore",
    "AuditSink",
    "BackendContext",
    "BackendContractError",
    "BackendOutput",
    "BackendUnavailable",
    "BuiltinBackend",
    "BuiltinRunner",
    "ExecutionBackendPort",
    "ExecutionDenied",
    "ExecutionError",
    "ExecutionLedger",
    "ExecutionOutcome",
    "ExecutionService",
    "ExegolAdapter",
    "ExegolProbe",
    "FakeExecutionBackend",
    "FakeResponse",
    "FindingStore",
    "IdempotentReplay",
    "InMemoryAttemptStore",
    "InMemoryExecutionLedger",
    "InMemoryFindingStore",
    "ProfileRegistry",
    "ProfileUnknown",
    "all_profiles",
    "build_command",
    "detect_exegol",
    "profile",
    "resolve_argv",
    "validate_argv_template",
]
