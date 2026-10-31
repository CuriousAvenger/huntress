# AGENTS.md

Huntress is a security-critical system. Treat every change as a change to the
authorization boundary, even when it looks like a small refactor.

## Non-negotiable trust boundaries

1. **The model is untrusted input.** Never let model output supply a URL,
   command, shell, argument, file path, profile definition, scope change,
   budget, approval, or target. Models may only reference reviewed IDs.
2. **The policy gateway is the only authority.** Every side effect must pass
   `PolicyGateway.evaluate` or `recheck` with a sealed scope, approved target,
   reviewed profile, valid approval, and available budget.
3. **The controller owns lifecycle.** Do not mutate engagement state, budgets,
   approvals, or the ledger outside `Controller` and the repository APIs.
4. **Scope is sealed.** Never edit a compiled `ScopeDocument` in place, bypass
   `verify_scope_seal`, or trust a scope loaded without seal verification.
5. **Approvals bind to content.** Never reuse an approval for a different
   action fingerprint, scope hash, report content hash, or destination.
6. **Evidence is immutable.** Do not rewrite, truncate, or delete raw artifacts.
   Derived data gets a new artifact and parent provenance.
7. **Human gates are permanent.** High-risk/exploit-like live actions and every
   report submission require a named human. Low-risk preauthorization is a
   narrow scope policy, not a runtime bypass.
8. **No live targets in tests or CI.** Use the loopback lab, replay fixtures,
   and the explicit fake backend.

If a task appears to require violating one of these rules, stop and ask for an
explicit design decision. Do not implement a silent fallback.

## Dependency direction

The import-linter contracts in `pyproject.toml` are part of the test suite.

- `huntress-contracts` imports no application package or model SDK.
- `huntress-governance` must not import execution, scanning, verification,
  reasoning, persistence, or orchestrator.
- `huntress-execution` must not import reasoning or model SDKs.
- `huntress-reasoning` must not import execution, scanning, verification,
  persistence, or orchestrator.
- Scanning, verification, and reporting must not import model SDKs.
- Evidence must not import policy, execution, verification, or reasoning.

When adding a dependency, update the relevant package `pyproject.toml`, the
workspace `uv.lock`, and the import-linter contracts if the direction changes.

## Coding rules

- Python 3.12, full type annotations, `from __future__ import annotations`.
- Pydantic contracts are frozen and `extra="forbid"`. Add fields deliberately
  and version incompatible changes.
- Use `utc_now()` / `ensure_utc()` for timestamps. Never use naive datetimes.
- Use repository APIs for persistence; do not hand-write SQL outside
  `huntress-persistence`.
- Use `new_id(prefix)` for identifiers and `sha256_hex`/`canonical_json` for
  hashes.
- Keep public APIs small and explicit. Prefer typed dataclasses/contracts over
  dictionaries at boundaries.
- Never log secrets, approval signatures, bearer tokens, raw credentials, or
  model API keys.
- Error messages must be actionable and must not include sensitive values.
- Tests must be deterministic. Do not sleep, hit the public internet, or rely
  on wall-clock timing beyond bounded expiry checks.

## Change checklist

Before opening a change:

- [ ] Does the change touch scope, approval, budget, evidence, or execution?
      If yes, add a negative test for the bypass you are trying to prevent.
- [ ] Are model-supplied values still impossible to execute?
- [ ] Is the action fingerprint / scope hash / content hash binding preserved?
- [ ] Are new audit events append-only and correlation IDs present?
- [ ] Are artifacts content-addressed with provenance?
- [ ] Is the new behavior covered by unit, policy, integration, or lab tests?
- [ ] Did you update docs and the threat model for a new trust boundary?
- [ ] Did you run the full `make check` suite?

## Commands

```bash
uv sync --all-packages
uv run ruff check .
uv run mypy packages
uv run lint-imports
uv run pytest -q
uv run python evals/scorecard.py
```

Use `uv run pytest -q tests/policy` for fast policy feedback and
`uv run pytest -q tests/e2e_lab` for the real builtin scanner against the
loopback lab.

## Review expectations

Security-critical paths require a second reviewer:

- `packages/governance/`
- `packages/execution/`
- `packages/verification/`
- `packages/orchestrator/src/huntress_orchestrator/controller.py`
- `packages/orchestrator/src/huntress_orchestrator/cli.py`
- `packages/persistence/src/huntress_persistence/db.py`
- `packages/persistence/src/huntress_persistence/repositories.py`

Do not approve a change merely because it adds candidates. It must preserve
policy invariants and improve validated-finding quality or a measured
operational property.
