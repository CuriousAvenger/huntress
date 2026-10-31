# Incident Response Runbook

Use this runbook for suspected policy bypass, out-of-scope execution, leaked
credentials, malicious target content, audit-chain failure, or an unexpected
report submission.

## Principles

1. Stop side effects first.
2. Preserve evidence before cleaning up.
3. Do not destroy logs, artifacts, ledger entries, or approvals.
4. Notify the responsible humans and program contact as required.
5. Record decisions and timestamps in an incident log.
6. Fix the cause, add a regression test, and re-run the full release gates.

## Immediate containment

- Stop the Huntress process.
- Cancel or close the affected engagement through the CLI if the process is
  still running and cancellation is safe:
  `uv run huntress engagement cancel <ENGAGEMENT_ID> --reason "incident containment"`.
- If a report was submitted unexpectedly, contact the destination program
  immediately and follow its retraction process.
- If a signing key or Exegol/model token may be exposed, revoke/rotate it now.
- If the host may be compromised, isolate it from the network without deleting
  the data directory.

Do not delete `.huntress/`, the database, artifacts, `.env`, or audit rows.

## Triage questions

- Which engagement, target, profile, action request, approval, and attempt were
  involved?
- Was the action allowed by policy, and which policy version/scope hash was in
  effect?
- Was the target inside the sealed scope at the time?
- Was a human approval present, valid, unexpired, and bound to the exact action
  fingerprint and scope hash?
- Did the execution backend run, and what artifacts/exit status were recorded?
- Was any report drafted, approved, or submitted? To which destination?
- Is the audit chain still valid?
- Were credentials, tokens, or sensitive target data exposed in logs, reports,
  or model context?

Useful commands (run read-only first):

```bash
uv run huntress status <ENGAGEMENT_ID>
uv run huntress findings list <ENGAGEMENT_ID>
uv run huntress audit list --engagement <ENGAGEMENT_ID>
uv run huntress audit verify --engagement <ENGAGEMENT_ID>
uv run huntress report list <ENGAGEMENT_ID>
```

## Scenario playbooks

### Suspected out-of-scope action

1. Stop the process and cancel the engagement.
2. Preserve the database, artifacts, and terminal history.
3. Identify the target, scope hash, policy decision, approval, and action
   ledger entry.
4. Verify the target against the sealed scope and exclusions.
5. Check whether a scope changed after approval or whether a redirect expanded
   the target.
6. Notify the program contact and follow disclosure/notification obligations.
7. Add a regression test reproducing the bypass, fix it, and re-run policy,
   integration, and lab tests.

### Leaked signing key

Assume every scope and approval seal is untrusted.

1. Stop Huntress.
2. Revoke the key and any derived access.
3. Preserve the old key securely for investigation.
4. Recompile and reapprove every active scope under a new key.
5. Verify audit chains and inspect for forged scopes/approvals.
6. Notify reviewers and the program as required.
7. Document the rotation and reauthorization.

### Leaked Exegol or model token

1. Revoke the token at the provider/Exegol endpoint.
2. Inspect MCP/model call audit records for unexpected use.
3. Rotate the token and update `.env`/secret storage.
4. Re-run health checks and a fake-backend test.
5. If the model provider was used with sensitive context, assess disclosure and
   notify as required.

### Malicious target content / prompt injection

1. Preserve the raw artifact; do not edit it.
2. Confirm the content was fenced as untrusted and never executed.
3. Check whether any decision/hypothesis referenced it as authority; invalid
   drafts should have been rejected.
4. Add the payload to `evals/fixtures/prompt_injection.json` and re-run the
   scorecard.
5. Review the context compiler and planner for any path that treats target text
   as authorization.

### Audit chain invalid

1. Stop writes to the affected database.
2. Preserve a copy of the database and WAL/SHM files.
3. Identify the first invalid event and whether the cause is corruption,
   storage failure, or tampering.
4. Restore from a known-good backup only after preserving the failed copy.
5. Re-run `audit verify` and document the gap.
6. If tampering is suspected, treat it as a host compromise.

### Unexpected report submission

1. Contact the destination program immediately.
2. Preserve the report content hash, approval record, destination, and audit
   events.
3. Determine whether the content hash or destination changed after approval.
4. If a bypass is found, disable submission paths until fixed.
5. Follow the program's retraction and notification process.

## Recovery criteria

Do not resume live work until:

- the cause is understood and fixed;
- a regression test covers the failure;
- `make check` passes;
- affected scopes are recompiled and reapproved;
- affected credentials are rotated;
- the program contact has been notified as required;
- the incident log and postmortem are complete.

## Postmortem template

- Summary and severity
- Timeline (UTC)
- Affected engagements/targets/data
- Root cause
- Policy or control that failed
- Detection and response quality
- Evidence preserved
- Notification/retraction status
- Corrective actions with owners and dates
- Regression tests added
- Residual risk
