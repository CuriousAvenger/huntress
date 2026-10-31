# Operations Runbook

Routine operation of a single-user Huntress deployment.

## 1. First install

```bash
uv sync --all-packages
uv run huntress init
uv run huntress health --no-probe-exegol
```

`init` creates the data directory, applies SQLite migrations, creates the
signing key if absent, and installs the reviewed knowledge seed corpus.

Verify:

- database integrity is `ok`;
- schema version is current;
- artifact store is writable;
- signing key path is correct and mode is `0600`;
- `backend_mode` matches the intended mode.

## 2. Configuration

Use environment variables or `.env` for secrets. Never commit `.env`.

```bash
cp .env.example .env
chmod 600 .env
```

Set at minimum:

- `HUNTRESS_DATA_DIR`
- `HUNTRESS_MODE` (`lab`, `bounty`, or `shadow`)
- `HUNTRESS_OPERATOR`
- `HUNTRESS_EXEGOL_BACKEND`
- model provider settings if reasoning is enabled

`config/defaults.toml` contains reviewed non-secret defaults. Environment
values override TOML.

## 3. Backup

Back up together:

1. the signing key (`signing.key` or `HUNTRESS_SIGNING_KEY_FILE`);
2. the SQLite database (`huntress.db`, plus `-wal`/`-shm` when stopped);
3. the artifact directory;
4. the configuration and `.env` (secrets handled separately).

A backup without the signing key cannot verify existing scopes or approvals.
Encrypt backups at rest and restrict access.

Restore procedure:

1. Stop Huntress.
2. Restore the database and artifacts to the configured paths.
3. Restore the same signing key.
4. Run `huntress health --no-probe-exegol`.
5. Run `huntress audit verify` for each engagement.
6. Do not resume a blocked engagement until the cause is understood.

## 4. Signing-key rotation

Rotating the key invalidates every existing scope and approval seal. Treat it
as a planned re-authorization event:

1. Stop Huntress and notify reviewers.
2. Preserve the old key in a secure archive for audit.
3. Install the new key.
4. Recompile and reapprove every active scope.
5. Record the rotation in the incident/change log.
6. Run the policy and lab test suites before resuming live work.

If rotation is suspected to be compromise-driven, follow
`docs/runbooks/incident-response.md` instead.

## 5. Daily checks

```bash
uv run huntress health --no-probe-exegol
uv run huntress engagement list
uv run huntress audit verify --engagement <ENGAGEMENT_ID>
uv run huntress status <ENGAGEMENT_ID>
```

Check:

- no unexpected `BLOCKED` engagements;
- pending approvals are current and not near expiry;
- budgets and rate limits are healthy;
- audit chain is valid;
- artifact store has free space;
- no unexpected backend mode or model provider.

## 6. Local lab smoke test

```bash
make smoke
```

The script uses a fresh temporary data directory, starts the loopback lab,
creates an engagement and scope, scans for exposed files, validates, reviews,
drafts/approves/submits a report, and verifies the audit chain. It does not
contact a public target, Docker, Exegol, or a model provider. Set
`HUNTRESS_SMOKE_KEEP=1` to retain the temporary data directory for inspection.

## 7. Exegol

Start the Exegol MCP server and configure:

```bash
# Run `exegol-mcp --print-config` and copy the bearer token into a secret
# manager or your shell's protected environment. Do not paste it into shell
# history or commit it.
export HUNTRESS_EXEGOL_BACKEND=exegol
export HUNTRESS_EXEGOL_URL=http://127.0.0.1:2187/mcp
export HUNTRESS_EXEGOL_CONTAINER=pentest
export HUNTRESS_EXEGOL_TOKEN="<token-from-exegol-mcp>"
uv run huntress health
```

The adapter refuses non-private endpoints unless
`HUNTRESS_EXEGOL_ALLOW_REMOTE=true` is explicitly set after a network review.
It only calls `execute_command_in_container`; it never exposes arbitrary MCP
tools to the model.

If Docker permissions are unavailable, use `HUNTRESS_EXEGOL_BACKEND=fake` in
lab mode for tests. Do not use fake mode for live work.

## 8. Blocked engagements

A `BLOCKED` engagement indicates an execution refusal or a validation scope
failure. Do not resume blindly.

1. Run `huntress status <ENGAGEMENT_ID>`.
2. Inspect `huntress audit list --engagement <ENGAGEMENT_ID>`.
3. Inspect the attempt/result and evidence references.
4. Determine whether the cause was scope expiry, policy denial, backend
   failure, or validation integrity.
5. Fix the cause (new scope version, backend recovery, evidence issue).
6. Resume explicitly with a reason:

```bash
uv run huntress engagement resume <ENGAGEMENT_ID> --reason "cause investigated; scope re-approved"
```

The resume is audited. It does not clear prior evidence or rewind the ledger.

## 9. Budget and rate limits

Budget reservations are transactional. If a process crashes between reservation
and settlement, inspect the reservation state before retrying. Do not manually
delete ledger or reservation rows to force a retry; that destroys idempotency
and audit evidence.

Prefer a new action request with a new idempotency key after confirming the
prior action did not execute.

## 10. Data retention

`HUNTRESS_EVIDENCE_RETENTION_DAYS` is a policy input, not an automatic
deletion job. Deletion requires an explicit, reviewed procedure because raw
artifacts are evidence. Preserve audit records and report approvals for the
period required by the program and applicable law.

## 11. Upgrade procedure

```bash
git pull
uv sync --all-packages
uv run ruff check .
uv run mypy packages
uv run lint-imports
uv run pytest -q
uv run python evals/scorecard.py
uv run huntress health --no-probe-exegol
```

Review migration changes and back up before upgrading a live data directory.
Run the lab smoke test after any policy, execution, validation, or persistence
change.
