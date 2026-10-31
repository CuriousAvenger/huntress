# Data Contracts

Huntress contracts are frozen Pydantic models with `extra="forbid"`. They are
the vocabulary shared by the controller, policy, persistence, evidence,
validation, reasoning, and reporting layers.

## Identifiers

IDs are opaque, prefixed, and generated with UUID4. They are never sequence
numbers, so they do not leak volume or ordering.

| Prefix | Record |
| --- | --- |
| `eng_` | Engagement |
| `scope_` | Sealed scope |
| `asset_` | Scope asset |
| `tgt_` | Target record |
| `req_` | Action request |
| `pol_` | Policy decision |
| `apr_` | Approval request/record |
| `att_` | Test attempt |
| `exe_` | Execution request |
| `tf_` | Tool finding |
| `vf_` | Validated finding |
| `hyp_` | Hypothesis |
| `dec_` | Investigation decision |
| `rpt_` | Report |
| `ku_` | Knowledge unit |
| `aud_` | Audit event |
| `br_` | Budget reservation |
| `rev_` | Review record |

The exact regex is part of the contract. Do not accept arbitrary strings where
an ID is expected.

## Core contracts

### Engagement and scope

- `Engagement`: identity, mode, state, program, scope ID/version, policy
  version, budget limits, timestamps, creator, notes.
- `ScopeDraft`: requested assets, methods, profiles, preapproved profiles,
  testing window, ROE, reporting rules, authorization reference.
- `ScopeAsset`: kind, value, provenance, policy status, allowed ports/paths/
  methods, expiry.
- `ScopeDocument`: compiled, approved, sealed scope with content hash and
  signature.
- `ScopeExclusion`: kind, value, reason, creator.

### Actions and policy

- `ActionRequest`: engagement, action kind, target ID, profile ID, hypothesis
  ID, evidence IDs, idempotency key, requester, source, timestamp. It has no
  URL, command, argument, budget, or scope field.
- `PolicyDecision`: allowed/denied, stable reason code, reasons, policy version,
  scope hash, action fingerprint, budget snapshot, approval requirement/ID,
  decision time, expiry, decision hash.
- `ApprovalRequest` / `ApprovalRecord`: action fingerprint, scope hash,
  requester/approver, reason/note, status, timestamps, content hash, signature.
- `ActionLedgerEntry`: idempotency key, request, engagement, action fingerprint,
  status, timestamps, artifact/result/error references.
- `BudgetLimits`, `BudgetUsage`, `BudgetSnapshot`, `BudgetReservation`:
  action/model/token/cost/wall-clock ceilings, host/engagement rate limits,
  concurrency, usage, reservations.

### Execution and evidence

- `ExecutionRequest`: execution ID, request ID, policy decision ID, attempt ID,
  target/profile/version, idempotency key, deadline.
- `TestAttempt`: durable authorization trail and result summary for one run.
- `ToolRunResult`: status, exit code, output references, timing, truncation,
  timeout, error, request count, side effect class, backend.
- `ArtifactRef` / provenance: SHA-256 content hash, engagement/asset IDs,
  acquisition time, source tool/profile/version, action/policy version, parent
  artifacts, exit status, redaction status, storage location.
- `ToolFinding`: typed observation, confidence, bug class, CWE, oracle hint,
  artifact references, excerpt, details, evidence fingerprint.

### Validation and reporting

- `ValidatedFinding`: target, bug class, oracle archetype, claim, evidence,
  six gate results, reproduction policy, severity, dedup, status, human review
  projection.
- `GateResult`: gate name, status, reason, evidence references, checker
  version, checked time.
- `VulnerabilityReport`: findings, content, content hash, destination, status,
  approval record, submission metadata.
- `HumanReview`: append-only reviewer decision, notes, timestamp.

### Reasoning

- `ContextPacket`: fixed nine sections, allowed IDs, context hash, token
  estimate, untrusted-content flag.
- `DecisionDraft` / `HypothesisDraft`: strict model output schemas with known
  IDs and no executable fields.
- `InvestigationDecision` / `VulnerabilityHypothesis`: server-assigned records
  with source, timestamps, and attribution.

## Persistence schema

SQLite migrations are versioned in `huntress-persistence`. The current schema
includes:

- `engagements`, `scopes`, `targets`;
- `action_requests`, `approvals`, `attempts`, `findings`, `validations`,
  `reviews`, `reports`;
- `budgets`, `budget_reservations`, `action_ledger`, `rate_windows`;
- `state_transitions`, `checkpoints`;
- `model_calls`, `decisions`, `hypotheses`;
- `knowledge_units`, `knowledge_fts`;
- `audit_events`.

Records are stored as validated JSON alongside indexed columns for lookup.
Writes use transactions. Foreign keys, WAL, `synchronous=FULL`, and a busy
timeout are enabled.

The action ledger is insert-if-absent for idempotency. Budget reservations are
transactional and settle to committed or released. Audit events are
append-only through the repository API.

## Evidence store

Artifacts are stored by SHA-256 under the configured artifact directory. Each
artifact has a provenance sidecar. Reads verify the hash; a mismatch is an
integrity failure, not a warning.

Rules:

- Raw output is immutable.
- Derived or sanitized output gets a new hash and parent links.
- A finding references artifacts by hash, never by a user-supplied path.
- Artifact metadata records engagement, target, profile, policy version,
  acquisition time, source, and redaction status.
- The store enforces a maximum artifact size.

## Hashing and sealing

- `canonical_json` sorts keys, uses compact separators, and rejects NaN.
- `sha256_hex` hashes bytes or UTF-8 text.
- `model_self_hash` hashes a model excluding its own hash/signature fields.
- Scope seals are HMAC-SHA256 over the scope content hash.
- Approval seals are HMAC-SHA256 over the approval content hash.
- The audit chain hashes each event including the previous event hash.
- Report content hashes exclude workflow fields so transitions do not
  invalidate approved content.

## Versioning

- Contract version is declared in `huntress-contracts`.
- Policy version embeds the policy generation, scope version, and scope hash
  prefix.
- Profile versions and config hashes are immutable registry data.
- Schema migrations are forward-only and tracked by `PRAGMA user_version`.
- Changing a contract shape or policy rule requires tests, docs, and an
  explicit migration/review plan. Do not silently reinterpret persisted data.

## Trust rules

- A model-supplied value is data, never authority.
- A missing field is not permission; ambiguity denies.
- A hash or signature mismatch fails closed.
- A record loaded from storage is revalidated before a side effect.
- A report is not submittable merely because it exists; it must be approved
  against its current content hash and destination.
