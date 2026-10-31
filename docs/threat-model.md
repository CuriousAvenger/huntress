# Threat Model

Huntress performs security testing. The primary risk is not only that it misses
a vulnerability, but that it acts outside authorization, leaks sensitive data,
or presents an unverified claim as fact.

## Assets

- Authorization scope, ROE, testing window, and exclusions.
- Human approvals and report submission authorization.
- Engagement state, budgets, action ledger, and checkpoints.
- Raw evidence, credentials, tokens, and target-controlled content.
- Signing keys, Exegol bearer tokens, and model provider keys.
- Audit records and the integrity of the hash chain.
- The reputation and legal standing of the operator and program.

## Actors and trust boundaries

| Actor | Trust | Boundary |
| --- | --- | --- |
| Operator | Trusted human | CLI, scope approval, action approval, report approval |
| Model provider | Untrusted computation | Reasoning service; receives fenced context only |
| Target responses | Untrusted data | Evidence store; never executed, never treated as instructions |
| Exegol MCP server | Semi-trusted tool boundary | Fixed-profile adapter; one tool; local endpoint by default |
| Builtin scanner | Trusted application code | In-process HTTP client with scope authorizer |
| SQLite / artifact store | Trusted local storage | Repository and evidence APIs |
| CI | Untrusted with no live targets | Local lab, replay fixtures, fake backend |

The model is never on the authorization path. A compromised model can waste
budget or propose bad IDs, but the policy gateway and validators reject any
action outside the sealed scope.

## Threat and control matrix

| Threat | Required control | Implementation / test |
| --- | --- | --- |
| Out-of-scope request from model | Known IDs only; deterministic scope guard before every action | `ScopeGuard`, `PolicyGateway`, `tests/policy` |
| Scope tampering or authorization expiry | Sealed scope; expiry and seal recheck before execution/validation | HMAC scope seal, `verify_scope_seal`, expiry tests |
| Scope change invalidates pending approval | Approval binds scope hash and action fingerprint | `ApprovalService.verify`, policy tests |
| Replay after crash | Idempotency ledger with atomic reservation | `ActionLedgerEntry`, execution service, policy tests |
| Budget or tool loop runaway | Transactional action/model/token/cost/rate limits and deadlines | `BudgetManager`, SQLite reservations |
| Indirect prompt injection | Raw artifacts outside planner context; sanitized nonce fences; typed extraction | `ContextCompiler`, `evals/scorecard.py` |
| Model fabricates impact | Evidence-required validation; deterministic oracle; human review | Six validation gates, review records |
| Duplicate submissions | Exact fingerprint and similarity dedup before review | `DeduplicationGate` |
| Exegol exposes too much capability | Narrow adapter, fixed profile allowlist, one MCP tool, no model access | `ExegolAdapter`, argv validation tests |
| Command injection through profile values | Fixed argv templates, server-side placeholders, metacharacter rejection, `shlex.join` | `validate_argv_template`, `build_command` |
| Tool container escape | Least privilege, minimal mounts, no Docker socket, egress limits, patched images | Deployment runbook / Docker guidance |
| Credentials leak to scanner | Secrets only in control/reasoning environment; no model keys in scanner images | Config separation, Dockerfiles |
| Sensitive data in logs/reports | Redaction, artifact references, access control, retention | Evidence provenance, report review |
| Cross-program leakage | Tenant/program keys on state and retrieval; explicit tenant binding | Knowledge service tests |
| Audit tampering | Append-only API, hash chain, verification command | `AuditRepository.verify_chain`, lab test |
| Fake backend accidentally used in production | Fake allowed only in lab mode; explicit mode selection | `Settings` validator, execution selection tests |
| Non-local Exegol endpoint | Refuse non-private endpoints unless explicitly allowed | `ExegolAdapter` constructor |
| Public target in lab mode | Loopback/private/suffix allowlist unless `allow_public_lab` | `ScopeCompiler` tests |

## Abuse cases and expected denials

- Model proposes a URL or shell command instead of an ID: schema validation
  rejects the field; there is no execution field to populate.
- Model proposes a known profile against an unregistered target: policy returns
  `DENIED_TARGET_NOT_FOUND`.
- Model proposes an active profile without approval: policy returns
  `DENIED_APPROVAL_REQUIRED`; the controller persists an approval request.
- Approval is reused for a different target/profile/evidence set: fingerprint
  mismatch returns `DENIED_APPROVAL_INVALID`.
- Approval outlives its TTL: expiry returns `DENIED_APPROVAL_INVALID`.
- Scope is edited after approval: seal failure returns `DENIED_SCOPE_INTEGRITY`.
- Engagement is closed or cancelled: policy returns `DENIED_ENGAGEMENT_STATE`.
- Budget is exhausted: policy returns `DENIED_BUDGET_EXHAUSTED` or
  `DENIED_RATE_LIMITED`.
- Duplicate action retry: ledger returns `DENIED_IDEMPOTENT_REPLAY`.
- Report content changes after approval: content hash mismatch blocks
  submission.
- Target response contains instructions: context compiler fences them as
  untrusted data; planner never treats them as authorization.

## Residual risks

- A compromised host can read the SQLite database, artifact store, signing key,
  or process memory. Local-first isolation is not a substitute for host
  hardening.
- A compromised Exegol MCP server can return malicious output or lie about
  execution. The adapter caps output and preserves it as untrusted evidence,
  but cannot prove remote execution integrity.
- A compromised model provider can waste budget or propose plausible but wrong
  actions. Deterministic validation and human review remain the defense.
- Content-addressed dedup can collapse byte-identical probe responses; the
  differential oracle therefore relies on an explicit repetition count from the
  executor, not only unique artifact count.
- SQLite and local artifacts are single-user assumptions. Multi-user deployment
  requires PostgreSQL/object storage, per-tenant keys, and stronger access
  control.
- The builtin profile set is small. New domains can introduce parser or oracle
  blind spots until they have dedicated fixtures and evals.
- Human reviewers can make mistakes. The system records identity, content hash,
  and destination, but does not eliminate reviewer error.

## Security invariants to preserve

1. No model-controlled command, URL, path, or argument reaches a backend.
2. No execution without a sealed scope, approved target, reviewed profile, and
   current policy decision.
3. No high-risk/exploit-like live action without a named-human approval.
4. No report submission without a named-human approval bound to content and
   destination.
5. No artifact rewrite; derived data gets a new hash and parent link.
6. No audit mutation through application APIs.
7. No silent fallback from a real backend to the fake backend.
8. No live target in CI.

## Reporting a security issue

Do not open a public issue for a suspected policy bypass, key exposure, or
out-of-scope execution. Follow `docs/runbooks/incident-response.md` and contact
the maintainers privately.
