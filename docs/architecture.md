# Architecture

Huntress is a modular monolith with one durable controller and two isolated
execution boundaries: an in-process deterministic HTTP scanner and an optional
Exegol MCP adapter. The application, not the model, owns scope, state, policy,
budgets, evidence, and reporting.

## Component overview

```text
┌──────────────────────────────────────────────────────────────────────────┐
│ CLI (`huntress`) / future API                                            │
└───────────────────────────────┬──────────────────────────────────────────┘
                                │ typed commands
┌───────────────────────────────▼──────────────────────────────────────────┐
│ Orchestrator Controller                                                  │
│  lifecycle · scope · targets · actions · validation · review · reports  │
│  checkpoints · audit correlation                                         │
└───────┬───────────────┬──────────────────┬──────────────────┬────────────┘
        │               │                  │                  │
        │               │                  │                  │
┌───────▼──────┐ ┌──────▼───────┐ ┌────────▼────────┐ ┌───────▼─────────┐
│ Governance   │ │ Reasoning    │ │ Verification    │ │ Reporting       │
│ scope seal   │ │ context      │ │ six gates       │ │ content hash    │
│ approvals    │ │ Strands      │ │ oracles         │ │ human approval  │
│ budget       │ │ rule planner │ │ dedup/review    │ │ submission      │
│ policy       │ │ schemas      │ │                 │ │                 │
└───────┬──────┘ └──────┬───────┘ └────────┬────────┘ └───────┬─────────┘
        │               │                  │                  │
        └───────────────┴──────────┬───────┴──────────────────┘
                                   │
                     ┌─────────────▼─────────────┐
                     │ Persistence + Evidence    │
                     │ SQLite · audit chain      │
                     │ content-addressed store   │
                     └─────────────┬─────────────┘
                                   │
                     ┌─────────────▼─────────────┐
                     │ ExecutionService          │
                     │ recheck · reserve · run   │
                     │ capture · settle          │
                     └──────┬──────────┬─────────┘
                            │          │
                 ┌──────────▼──┐  ┌────▼─────────────┐
                 │ Builtin     │  │ Exegol MCP       │
                 │ HTTP scanner│  │ fixed profiles   │
                 └─────────────┘  └──────────────────┘
```

## Authority flow for one action

1. The operator or planner calls `Controller.request_action` with a profile ID
   and target ID. The request contains no URL or command.
2. The controller persists an `ActionRequest` with a unique idempotency key and
   records an audit event.
3. `PolicyGateway.evaluate` checks:
   - engagement/request identity and non-terminal state;
   - scope testing window;
   - target existence, engagement ownership, in-scope flag, exclusions,
     asset match, port/path restrictions, and method allowlist;
   - profile existence, scope allowlist, supported asset kind, risk class, side
     effects, availability tag, exploit authorization, and declared methods;
   - idempotency ledger;
   - approval requirement and signature/fingerprint/scope/expiry binding;
   - action, host-rate, engagement-rate, token, cost, and wall-clock budgets.
4. If allowed and preauthorized, the controller transitions through
   `ACTION_PENDING → EXECUTING`, and the execution service rechecks everything
   except budget/ledger (which it reserves atomically).
5. If approval is required, the controller persists an `ApprovalRequest` and
   transitions to `WAITING_FOR_APPROVAL`. A named human approves or rejects.
6. The execution service resolves a reviewed profile, selects the backend,
   captures artifacts, persists findings/attempts, settles the budget, and
   writes the action ledger.
7. The controller returns to `ANALYSIS` and records an audit event.

There is no path from model output directly to a side effect. The model can
only produce a decision draft containing known IDs; `DecisionValidator`
rejects anything outside the packet, and the same policy gateway still runs.

## Durable state machine

```text
CREATED → SCOPE_PENDING → READY
READY ↔ RECON ↔ ANALYSIS
ANALYSIS → ACTION_PENDING → EXECUTING → ANALYSIS
ANALYSIS → WAITING_FOR_APPROVAL → ANALYSIS
ANALYSIS → VALIDATING → HUMAN_REVIEW → REPORT_DRAFT
REPORT_DRAFT → SUBMISSION_PENDING → CLOSED
any active state → BLOCKED → READY (explicit operator resume)
any non-terminal state → CANCELLED
any non-terminal state → CLOSED (operator close)
```

`CLOSED`, `CANCELLED`, and `FAILED` are terminal. `BLOCKED` is recoverable only
through the audited `engagement resume` command. State transitions and
checkpoints are persisted in the same repository layer as the engagement.

## Scope compilation and enforcement

`ScopeCompiler` validates a `ScopeDraft` against the reviewed profile registry,
then seals a `ScopeDocument` with an HMAC-SHA256 signature over its canonical
content hash. Assets are marked approved only inside the compiled document.

`ScopeGuard` is intentionally pessimistic:

- unknown or ambiguous target → deny;
- missing/unsigned/tampered scope → deny;
- expired testing window or asset → deny;
- exclusions win over allowlists;
- wildcard domains match subdomains only;
- URL assets match scheme, host, port, and path prefix exactly;
- redirects are candidates, never automatic scope expansion;
- lab mode permits only loopback/private/`.test`/`.local`/`.example`/`.internal`
  hosts unless the scope explicitly sets `allow_public_lab=true`.

## Discovery

`huntress-scanning-fleet` contains the reviewed builtin profiles. Each profile
is immutable configuration with a handler, allowed methods, risk class, side
effect class, timeout, request cap, parser, and oracle hint. The scanner:

- uses an allowlist of fixed paths/parameters;
- refuses redirects outside scope;
- caps request counts, response sizes, and timeouts;
- preserves raw request/response artifacts through the evidence store;
- emits typed `ToolFinding` records with an evidence fingerprint;
- never expands scope from a response.

## Validation

`huntress-verification` evaluates six independent gates for every candidate:

1. `scope_recheck` — target, method, window, and seal still valid;
2. `evidence_completeness` — artifacts exist, provenance is complete, and
   timestamps are inside the testing window;
3. `reproducibility` — performed repetitions meet the oracle policy;
4. `technical_oracle` — deterministic oracle over preserved artifacts;
5. `severity` — explicit operator band or CVSS vector;
6. `deduplication` — exact fingerprint or high-similarity prior finding.

Status precedence is: scope gate `FAIL` → `BLOCKED`; any other `FAIL` →
`FAILED`; any `INCONCLUSIVE`/non-`PASS` → `INCONCLUSIVE`; otherwise `PASSED`.
Only passed, unique, all-gates-pass findings can be human-approved and reported.

The model never supplies the verdict. Validation facts are derived from
artifacts and parser markers, not from model prose.

## Reasoning and context

`huntress-reasoning` compiles a fixed nine-section packet:

1. instructions
2. authorization
3. target brief
4. objective
5. evidence
6. knowledge
7. working memory
8. budget
9. output contract

Untrusted excerpts are sanitized and fenced with a content-derived nonce. The
packet is capped at 120,000 characters by default. Strict Pydantic draft
schemas reject unknown fields and require known target/profile/evidence IDs.
The server assigns IDs, timestamps, source, and attribution.

`RuleBasedPlanner` is the deterministic baseline: review unreviewed evidence,
ask for human review once evidence is reviewed, run the first unattempted
approved profile, then stop. The Strands runtime is only constructed when
model-backed reasoning is requested.

## Persistence and evidence

SQLite stores engagements, scopes, targets, action requests, approvals,
attempts, findings, validations, reviews, reports, budgets, model calls,
decisions, hypotheses, transitions, checkpoints, and knowledge units. Migrations
are versioned in `huntress-persistence`.

The artifact store writes bytes under their SHA-256 and a JSON provenance
sidecar. Reads verify the content hash. Derived artifacts must link to their
parents rather than overwrite raw output.

The audit log is append-only with a per-engagement SHA-256 hash chain. Each
event includes actor, action, outcome, correlation ID, policy version, optional
tool profile/model ID, and structured details. `audit verify` recomputes the
chain and event hashes.

## Reporting

`ReportBuilder` drafts from passed, unique, human-approved findings. The report
content hash excludes workflow fields (`content_hash`, `approval`, `status`,
`content_ref`) so approval and submission transitions do not invalidate the
approved content. Submission approval requires:

- a named human;
- a concrete destination matching the report;
- current passed/approved findings;
- a valid content hash;
- the engagement in `SUBMISSION_PENDING`.

`submit_report` marks the report submitted and closes the engagement. There is
no automatic external submission adapter in this MVP.

## Failure handling

- An execution exception after invocation is recorded as a failed
  `ToolRunResult`; output is preserved.
- A policy refusal before invocation releases the budget reservation and marks
  the ledger failed.
- A duplicate idempotency key returns `IdempotentReplay`; the prior result must
  be retrieved rather than re-executed.
- A crash between reservation and execution leaves a reserved hold; recovery
  must release or reconcile it explicitly.
- Pending approvals survive process restarts because they are persisted before
  the controller returns.
- A blocked engagement cannot resume implicitly; an operator must provide a
  reason, which is audited.
