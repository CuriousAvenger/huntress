# Huntress

Huntress is a local-first, policy-enforced autonomous bug-bounty engine. It
combines a deterministic discovery and validation pipeline with a bounded
Strands reasoning layer, an isolated Exegol execution adapter, durable SQLite
state, and content-addressed evidence.

The application owns authority. A model may propose an action by referencing a
reviewed profile ID and a server-side target ID, but it cannot supply a URL,
command, shell, scope mutation, budget, or approval. Every executable action is
re-checked by the deterministic policy gateway immediately before it runs.

> **Status:** MVP / lab and shadow-mode implementation. The deterministic
> pipeline, CLI, fake Exegol backend, local lab, reporting workflow, and test
> suites are complete. The live Exegol MCP adapter is implemented and verified
> against the installed MCP client, but live execution depends on host Docker
> permissions. Do not point this at a target you are not explicitly authorized
> to test.

## What is implemented

- Sealed, HMAC-SHA256 scope documents with exact asset, method, port, path,
  exclusion, and testing-window enforcement.
- Human approval gates for active/high-risk profiles and for every report
  submission. Approvals bind to the action fingerprint and scope hash.
- Transactional SQLite budgets, rate limits, idempotency ledger, checkpoints,
  state transitions, and an append-only SHA-256 audit hash chain.
- Content-addressed artifact storage with provenance sidecars and integrity
  checks.
- Reviewed builtin HTTP profiles: baseline, security headers, exposed files,
  CORS, open redirect, reflected marker, and differential error-based SQLi.
- Six independent validation gates: scope recheck, evidence completeness,
  reproducibility, technical oracle, severity, and deduplication.
- Append-only human review records and deterministic report drafting.
- Strands reasoning with strict draft schemas, fenced untrusted evidence,
  budgeted model calls, and a rule-based fallback planner.
- A narrow Exegol MCP adapter that only calls
  `execute_command_in_container`, only uses fixed argv templates, rejects
  shell metacharacters, shell-quotes resolved values, and refuses non-local
  endpoints by default.
- A deterministic local vulnerable lab and an offline reasoning scorecard.

## Requirements

- Python 3.12
- [uv](https://docs.astral.sh/uv/)
- Optional: a local [LM Studio](https://lmstudio.ai/) server for model-backed
  reasoning
- Optional: a local Exegol MCP endpoint for container-backed profiles

## Quick start

```bash
uv sync --all-packages
uv run huntress init
uv run huntress health --no-probe-exegol
```

Start the deterministic local lab in a second terminal:

```bash
uv run huntress lab serve --host 127.0.0.1 --port 18080
```

Create an engagement, seal a lab scope, and run the preauthorized exposed-file
profile:

```bash
uv run huntress engagement create --name demo
# Use the printed engagement ID in the next commands.
uv run huntress scope set <ENGAGEMENT_ID> \
  --asset http://127.0.0.1:18080 \
  --authorization-ref "local lab only" \
  --approved-by "Your Name"
uv run huntress target sync <ENGAGEMENT_ID>
uv run huntress scan <ENGAGEMENT_ID> --profile http.exposed_files
```

Inspect the findings, then validate, review, and draft a report:

```bash
uv run huntress findings list <ENGAGEMENT_ID>
uv run huntress validate <ENGAGEMENT_ID> \
  --finding <TOOL_FINDING_ID> \
  --bug-class bug_env_exposure \
  --title "Publicly exposed dotenv configuration" \
  --claim "The lab served a dotenv file containing credential-shaped assignments." \
  --severity high
uv run huntress review <VALIDATED_FINDING_ID> \
  --reviewer "Your Name" --decision approved
uv run huntress report draft <ENGAGEMENT_ID> --destination manual
uv run huntress report request <REPORT_ID>
uv run huntress report approve <REPORT_ID> \
  --by "Your Name" --destination manual
uv run huntress report submit <REPORT_ID>
uv run huntress audit verify --engagement <ENGAGEMENT_ID>
```

Global flags such as `--json` and `--config` must precede the subcommand:

```bash
uv run huntress --json status <ENGAGEMENT_ID>
```

## Safety model

The following invariants are enforced in code and covered by tests:

1. **No unrestricted execution.** The model never receives shell, MCP, or
   arbitrary command access. It may only choose a reviewed profile ID against a
   registered target ID.
2. **Scope is authority.** Scope documents are sealed and verified before
   execution and validation. Ambiguous, expired, tampered, unapproved, or
   out-of-window scopes are denied.
3. **Human control is permanent.** Active/high-risk profiles require an
   explicit named-human approval. Every report submission requires a separate
   named-human approval bound to the exact content hash and destination.
4. **Evidence is immutable.** Raw outputs are stored by SHA-256 with provenance;
   validation reads preserved artifacts rather than trusting model prose.
5. **Budgets are transactional.** Actions, model calls, tokens, cost, wall
   clock, host rate, and engagement rate are reserved before use and settled
   after use.
6. **Failures are durable.** State transitions, action ledger entries,
   checkpoints, approvals, reviews, and audit events survive restarts.
7. **No live targets in CI.** Tests use the local lab, replay fixtures, and the
   explicit fake backend.

Lab mode refuses public targets unless a scope explicitly sets
`allow_public_lab=true`. The fake execution backend is only permitted in lab
mode.

## Architecture

```text
CLI / API
   |
   v
Orchestrator Controller  <---- durable SQLite state, checkpoints, audit
   |        |        |
   |        |        +--> Reporting (draft, human approval, submission)
   |        +------------> Verification (six deterministic gates, review)
   |
   +--> Reasoning (Strands, fenced context, strict schemas, budget)
   |
   +--> PolicyGateway (scope seal, target, profile, approval, budget, ledger)
             |
             v
        ExecutionService
          |         |
          |         +--> Builtin HTTP scanner (in-process)
          |         +--> Exegol MCP adapter (fixed profiles)
          |         +--> Fake backend (tests only)
          v
     Content-addressed evidence + provenance
```

The durable controller is authoritative. A Strands run is bounded and
advisory; it cannot mutate scope, budgets, approvals, or the action ledger.

### Package map

| Package | Responsibility |
| --- | --- |
| `huntress-contracts` | Frozen Pydantic contracts, enums, IDs, hashing |
| `huntress-governance` | Scope compiler/guard, approvals, budgets, policy gateway |
| `huntress-persistence` | SQLite migrations, repositories, audit chain, FTS knowledge |
| `huntress-evidence` | Content-addressed artifact store and provenance |
| `huntress-scanning-fleet` | Bounded builtin profiles, parsers, sweep digests |
| `huntress-execution` | Execution service, profile registry, Exegol/fake backends |
| `huntress-verification` | Reproduction, oracles, severity, dedup, human review |
| `huntress-knowledge` | Versioned knowledge units and tenant-bound retrieval |
| `huntress-reasoning` | Context compiler, prompts, schemas, Strands runtime |
| `huntress-reporting` | Deterministic report synthesis and submission workflow |
| `huntress-orchestrator` | Controller, CLI, lab server, configuration, wiring |

## Configuration

Configuration is flat and maps to `HUNTRESS_*` environment variables. The
precedence is explicit CLI/init values > environment > `.env` > TOML >
defaults. Reviewed defaults live in `config/defaults.toml`; secret placeholders
live in `.env.example`.

Common settings:

```bash
HUNTRESS_DATA_DIR=.huntress
HUNTRESS_MODE=lab                 # lab | bounty | shadow
HUNTRESS_EXEGOL_BACKEND=auto      # auto | exegol | fake
HUNTRESS_EXEGOL_URL=http://127.0.0.1:2187/mcp
HUNTRESS_EXEGOL_CONTAINER=pentest
HUNTRESS_MODEL_PROVIDER=openai_compatible
HUNTRESS_MODEL_ID=local-model
HUNTRESS_MODEL_BASE_URL=http://127.0.0.1:1234/v1
```

The signing key is created at `.huntress/signing.key` with mode `0600` if it is
not supplied. Back it up and protect it; losing it invalidates every sealed
scope and approval.

### Model-backed reasoning

Reasoning is disabled by default. To use a local LM Studio model:

```bash
export HUNTRESS_REASONING_ENABLED=true
export HUNTRESS_MODEL_PROVIDER=openai_compatible
export HUNTRESS_MODEL_BASE_URL=http://127.0.0.1:1234/v1
export HUNTRESS_MODEL_ID=your-loaded-model
uv run huntress reason <ENGAGEMENT_ID> --objective "Choose the next bounded test" --use-model
```

Model output is schema-validated and recorded, but it is never trusted as a
validation verdict. Invalid outputs are not persisted as decisions or
hypotheses. The runtime supports Anthropic, OpenAI, Bedrock, Ollama, and LiteLLM
providers; provider packages are imported lazily.

### Exegol MCP

The adapter targets the verified endpoint shape
`http://127.0.0.1:2187/mcp` (FastMCP streamable HTTP with bearer auth) and only
calls `execute_command_in_container(container_name, command)`. Start Exegol's
MCP server and place its token in `HUNTRESS_EXEGOL_TOKEN`. Non-local endpoints
are refused unless `HUNTRESS_EXEGOL_ALLOW_REMOTE=true` is set after a network
review.

If Docker permissions are unavailable, keep `HUNTRESS_EXEGOL_BACKEND=fake` in
lab mode. The fake backend is explicit and is never selected silently for an
Exegol profile in `auto` mode.

## Development

```bash
make sync          # uv sync --all-packages
make lint          # ruff check .
make typecheck     # mypy packages
make imports       # import-linter contracts
make test          # pytest (unit, policy, integration, lab, eval)
make eval          # offline reasoning scorecard
make check         # all of the above
make lab           # run the deterministic lab on 127.0.0.1:18080
make smoke         # CLI end-to-end lab smoke test
```

Useful focused commands:

```bash
uv run pytest -q tests/unit
uv run pytest -q tests/policy
uv run pytest -q tests/integration
uv run pytest -q tests/e2e_lab
uv run python evals/scorecard.py
```

No test reaches a public network target. The `lab` marker denotes tests that
start the loopback lab server and exercise the real builtin scanner.

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — components, data flow, and
  trust boundaries.
- [`docs/threat-model.md`](docs/threat-model.md) — assets, adversaries,
  mitigations, and residual risks.
- [`docs/scope-and-approval-policy.md`](docs/scope-and-approval-policy.md) —
  scope lifecycle and human gates.
- [`docs/data-contracts.md`](docs/data-contracts.md) — identifiers, contracts,
  persistence, evidence, and audit.
- [`docs/runbooks/operations.md`](docs/runbooks/operations.md) — routine
  operation, backup, and recovery.
- [`docs/runbooks/incident-response.md`](docs/runbooks/incident-response.md) —
  suspected policy bypass, leaked key, or unexpected execution.
- [`docker/README.md`](docker/README.md) — reference images, compose profiles,
  and the Exegol boundary.
- [`TODO.md`](TODO.md) — prioritized knowledge/context supply-chain work.
- [`AGENTS.md`](AGENTS.md) — coding rules and trust-boundary checklist.

## Known limitations

- Live Exegol execution requires host Docker permissions; the adapter and fake
  backend are tested without Docker.
- SQLite and local artifact storage are intended for a single-user MVP. The
  repository interfaces are designed to migrate to PostgreSQL and object
  storage later.
- The builtin scanner supports a deliberately small reviewed profile set. New
  domains require their own profiles, parsers, oracles, evals, and ROE review.
- Model-backed reasoning requires a reachable provider. The rule-based planner
  remains the deterministic fallback and eval baseline.
- Reporting produces local drafts and an audited submission record; it does not
  contain a live bug-bounty platform adapter.
