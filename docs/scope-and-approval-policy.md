# Scope and Approval Policy

This document defines the operational rules behind the sealed scope and the two
permanent human gates. Code is authoritative; this document explains the
intended policy and the review checklist.

## 1. Engagement modes

| Mode | Purpose | Live targets | Fake backend |
| --- | --- | --- | --- |
| `lab` | Local development, CI, and demos | Loopback/private/suffix only by default | Allowed |
| `bounty` | Authorized live bug-bounty work | Authorized scope only | Refused |
| `shadow` | Observe and draft without submission | Authorized scope only | Refused |

`lab` mode refuses public assets unless the compiled scope explicitly sets
`allow_public_lab=true`. That override is for an isolated, explicitly reviewed
lab, not for production convenience.

The fake execution backend is refused outside `lab` mode. `auto` selects the
builtin backend for builtin profiles and Exegol for Exegol profiles; it never
silently falls back to fake.

## 2. Scope lifecycle

1. **Draft.** The operator supplies assets, allowed methods, allowed profiles,
   preapproved profiles, ROE, testing window, authorization reference, and
   reporting metadata.
2. **Compile.** `ScopeCompiler` validates:
   - at least one asset and one allowed profile;
   - a future testing window;
   - an authorization reference;
   - profiles exist in the reviewed registry;
   - profile risk and side effects fit the ROE;
   - exploit-like profiles are authorized explicitly;
   - only low-risk, read-only, preauthorizable profiles are preapproved;
   - lab mode target restrictions.
3. **Seal.** The compiler computes a canonical content hash and HMAC-SHA256
   signature. Assets are marked approved inside the sealed document.
4. **Activate.** The controller saves the scope, sets the engagement policy
   version, and transitions `CREATED → SCOPE_PENDING → READY`.
5. **Enforce.** Every action and validation rechecks the seal, window, target,
   exclusions, and profile policy.
6. **Expire / close.** Expired windows deny actions. Closing or cancelling the
   engagement is terminal; pending approvals cannot execute.

Changing the scope creates a new version and invalidates approvals bound to the
old scope hash. There is no in-place scope edit.

## 3. Profile risk classes

| Class | Examples | Approval |
| --- | --- | --- |
| `PASSIVE` | DNS resolution | May be preauthorized only if low risk/read-only and listed |
| `LOW` | Baseline, headers, exposed files, CORS | May be preauthorized only if listed in the sealed scope |
| `ACTIVE` | Open redirect, reflected marker, SQLi differential, bounded port scan | Per-action human approval required |
| `EXPLOIT_LIKE` | Any state-changing or exploit proof | Per-action human approval and explicit ROE authorization |

Preauthorization is a scope-level allowlist, not a runtime toggle. A profile
that is not listed in `preapproved_profiles` requires approval even if it is
low risk.

Active and exploit-like profiles are never preauthorized. The CLI defaults to
low-risk HTTP profiles and only preapproves those by default.

## 4. Action approval

An `ApprovalRequest` is created when policy returns
`DENIED_APPROVAL_REQUIRED`. It binds:

- engagement ID and action request ID;
- the action fingerprint (engagement, action, target, profile, sorted evidence
  IDs);
- the current scope content hash;
- the requesting operator and reason;
- an expiry timestamp.

A named human approves or rejects. The resulting `ApprovalRecord` is sealed and
expires independently. Before execution, the gateway verifies the record's
status, engagement, fingerprint, scope hash, time window, and signature.

Reusing an approval for a different target, profile, evidence set, or scope
fails closed. An expired approval fails closed. A rejected approval returns the
engagement to `ANALYSIS`; it does not execute.

Pending approvals are persisted, so they survive process restarts. If the scope
changes while an approval is pending, approval fails because the scope hash no
longer matches.

## 5. Report submission approval

Every external report submission requires a separate named-human approval.

`ReportService.approve_submission` requires:

- the report exists and has a valid content hash;
- all included findings are passed, unique, and human-approved;
- the destination is concrete and matches the report;
- a named approver is supplied;
- the engagement is in `SUBMISSION_PENDING`.

The report content hash excludes workflow fields (`content_hash`, `approval`,
`status`, `content_ref`) so approval and submission transitions do not
invalidate the approved content. Any change to findings, title, summary,
impact, reproduction steps, remediation, references, platform, or destination
invalidates the approval.

`submit_report` marks the report submitted and closes the engagement. There is
no automatic external platform adapter in this MVP; an adapter must preserve the
same approval and content-hash checks.

## 6. Validation and review policy

A candidate is reportable only when:

- validation status is `PASSED`;
- dedup status is `UNIQUE`;
- all six gates are `PASS`;
- a human reviewer has approved it.

Rejected or needs-more-evidence findings return the engagement to `ANALYSIS`.
Review records are append-only; the finding's review fields are a projection of
the latest review.

## 7. Revocation and emergency stop

- **Cancel engagement:** terminal; stops new actions and approvals.
- **Close engagement:** terminal; use after work is complete.
- **Reject approval:** prevents that exact action; returns to analysis.
- **Expire scope:** change the testing window or let it lapse; all actions deny.
- **Rotate signing key:** invalidates existing scope and approval seals; treat
  as an incident and re-authorize from scratch.
- **Stop the process:** no in-memory action can continue; pending approvals and
  ledger state remain durable.
- **Blocked state:** an execution refusal or validation scope failure moves the
  engagement to `BLOCKED`; only an audited operator `engagement resume
  --reason ...` returns it to `READY`.

## 8. Operator checklist before a live engagement

- [ ] Written authorization and program policy are on file.
- [ ] Assets, exclusions, ports, paths, and methods are exact.
- [ ] Testing window is correct for the operator's timezone.
- [ ] ROE risk class and side effects match the program.
- [ ] Only reviewed profiles are allowed.
- [ ] Active/exploit-like profiles are not preapproved.
- [ ] Reporting destination and contact are correct.
- [ ] Signing key is backed up and access-controlled.
- [ ] Budgets and rate limits are appropriate for the program.
- [ ] A human reviewer is available for every approval gate.
- [ ] Incident contact and stop procedure are known.
