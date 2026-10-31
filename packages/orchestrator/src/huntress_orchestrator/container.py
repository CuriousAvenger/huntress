"""Application container: one place that wires durable state and services.

The container is deliberately explicit. Every dependency is constructed once
from validated settings, and the execution backends are the only components
that can reach the network or an Exegol container. The controller receives
this object rather than constructing services ad hoc, which keeps the policy,
budget, audit, and evidence boundaries identical in the CLI and in tests.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from huntress_contracts import ExecutionBackend as BackendMode
from huntress_evidence import ArtifactStore
from huntress_execution import (
    DEFAULT_PROFILE_REGISTRY,
    BackendOutput,
    BuiltinBackend,
    ExecutionBackendPort,
    ExecutionService,
    ExegolAdapter,
    ExegolProbe,
    FakeExecutionBackend,
    ProfileRegistry,
)
from huntress_governance import ApprovalService, BudgetManager, PolicyGateway, ScopeCompiler, ScopeGuard
from huntress_knowledge import KnowledgeService
from huntress_persistence import Database, RepositoryBundle
from huntress_reasoning import ContextCompiler, ReasoningService, StrandsRuntime
from huntress_reporting import ReportBuilder, ReportService
from huntress_scanning import ScanningBackend
from huntress_verification import HumanReviewService, ValidationService

from .config import Settings, load_settings

if TYPE_CHECKING:
    from pathlib import Path


class Container:
    """Wired application services and durable stores."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or load_settings()
        self.settings.ensure_directories()

        self.signing_key: bytes = self.settings.signing_key_bytes()
        self.database = Database(self.settings.database_path)
        self.database.migrate()
        self.repos = RepositoryBundle(self.database)
        self.store = ArtifactStore(
            self.settings.artifacts_path,
            max_artifact_bytes=self.settings.evidence_max_artifact_bytes,
        )

        self.scope_compiler = ScopeCompiler(self.signing_key)
        self.scope_guard = ScopeGuard()
        self.budget = BudgetManager(self.repos.budget)
        self.approval_service = ApprovalService()
        self.gateway = PolicyGateway(
            budget=self.budget,
            ledger=self.repos.ledger,
            scope_guard=self.scope_guard,
            approval_service=self.approval_service,
        )
        self.profiles: ProfileRegistry = DEFAULT_PROFILE_REGISTRY

        self.scanning = ScanningBackend(self.store)
        self.builtin_backend = BuiltinBackend(self.scanning)
        self.fake_backend: FakeExecutionBackend | None = (
            FakeExecutionBackend() if self.settings.exegol_backend is BackendMode.FAKE else None
        )
        self.exegol_backend: ExegolAdapter | None = self._build_exegol()
        self._execution_backend: ExecutionBackendPort | None = self.exegol_backend

        self.execution = ExecutionService(
            store=self.store,
            attempts=self.repos.attempts,
            findings=self.repos.findings,
            ledger=self.repos.ledger,
            budget=self.budget,
            gateway=self.gateway,
            scope_guard=self.scope_guard,
            profiles=self.profiles,
            builtin_backend=self.builtin_backend,
            exegol_backend=self._execution_backend,
            fake_backend=self.fake_backend,
            backend_mode=self.settings.exegol_backend,
            audit=self.repos.audit,
        )

        self.validation = ValidationService(
            store=self.store,
            validations=self.repos.validations,
            audit=self.repos.audit,
        )
        self.reviews = HumanReviewService(
            validations=self.repos.validations,
            reviews=self.repos.reviews,
            audit=self.repos.audit,
        )
        self.knowledge = KnowledgeService(
            repository=self.repos.knowledge,
            audit=self.repos.audit,
        )
        self.context_compiler = ContextCompiler(
            max_total_chars=self.settings.reasoning_max_context_chars
        )
        self.report_builder = ReportBuilder()
        self.reports = ReportService(
            reports=self.repos.reports,
            findings=self.repos.validations,
            audit=self.repos.audit,
        )
        self._reasoning: ReasoningService | None = None

        # Installing the reviewed seed corpus is idempotent and leaves no
        # duplicate audit entries when the units already exist.
        if self.repos.knowledge.count() == 0:
            self.knowledge.install_seeds()

    def _build_exegol(self) -> ExegolAdapter | None:
        if self.settings.exegol_backend is BackendMode.FAKE:
            return None
        return ExegolAdapter(
            url=self.settings.exegol_url,
            container=self.settings.exegol_container,
            token=self.settings.exegol_token_value(),
            timeout_seconds=self.settings.exegol_timeout_seconds,
            max_output_bytes=self.settings.exegol_max_output_bytes,
            allow_remote=self.settings.exegol_allow_remote,
        )

    def reasoning_service(self) -> ReasoningService:
        """Construct the model-backed service only when it is actually used."""

        if self._reasoning is None:
            runtime = StrandsRuntime(
                self.settings.model_settings(),
                max_turns=self.settings.model_max_turns,
            )
            self._reasoning = ReasoningService(
                runtime=runtime,
                budget=self.budget,
                calls=self.repos.model_calls,
                decisions=self.repos.decisions,
                hypotheses=self.repos.hypotheses,
                audit=self.repos.audit,
            )
        return self._reasoning

    def probe_exegol(self, timeout_seconds: float = 5.0) -> ExegolProbe:
        if self.exegol_backend is None:
            return ExegolProbe(
                available=False,
                reason="fake backend is configured; Exegol was not constructed",
                endpoint=self.settings.exegol_url,
            )
        return self.exegol_backend.probe(timeout_seconds=timeout_seconds)

    def health(self) -> dict[str, object]:
        database = self.database.health()
        artifacts = self.store.stats()
        return {
            "database": database,
            "artifacts": artifacts,
            "signing_key_path": str(self.settings.signing_key_path),
            "backend_mode": self.settings.exegol_backend.value,
            "mode": self.settings.mode.value,
            "knowledge_units": self.repos.knowledge.count(),
            "reasoning_enabled": self.settings.reasoning_enabled,
            "model_provider": self.settings.model_provider,
            "model_id": self.settings.model_id,
            "model_base_url": self.settings.model_base_url,
        }

    def close(self) -> None:
        if self.exegol_backend is not None:
            self.exegol_backend.close()


def build_container(
    settings: Settings | None = None,
    *,
    config_file: Path | str | None = None,
) -> Container:
    """Convenience factory used by the CLI and integration tests."""

    if settings is None:
        settings = load_settings(config_file=config_file)
    return Container(settings)


__all__ = ["BackendOutput", "Container", "build_container"]
