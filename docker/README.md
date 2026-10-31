# Docker scaffolding

These files are reference images and a local compose file. They are **not** a
supported production deployment and they have not been built on every host.
The repository's automated tests do not require Docker; live Exegol execution
does.

The design keeps three things separate:

1. **Policy and orchestration** run in the operator process.
2. **Exegol** runs reviewed tools in its own container through the Exegol MCP
   server. Huntress never gives the model a Docker socket or an MCP tool.
3. **Verification** is deterministic and has no model SDKs, credentials, or
   network dependency.

## Layout

| Path | Purpose |
| --- | --- |
| `exegol-execution/Dockerfile` | Minimal non-root sandbox with `curl`, `dig`, `nmap`, and `jq`. A reference for a narrow tool container, not a replacement for Exegol. |
| `verification/Dockerfile` | Installs only `huntress-verification` and its dependency closure. No reasoning package or model SDK. |
| `docker-compose.dev.yml` | Loopback lab, optional verification smoke, and an offline execution-sandbox smoke. |

## Build

Build the verification image from the **repository root** so the workspace
metadata and packages are in the build context:

```bash
docker build -f docker/verification/Dockerfile -t huntress-verification:dev .
```

Build the execution sandbox from its own directory:

```bash
docker build -f docker/exegol-execution/Dockerfile \
  -t huntress-execution-sandbox:dev docker/exegol-execution
```

Smoke the images:

```bash
docker run --rm --network none huntress-verification:dev \
  -c "import huntress_verification; print('verification ready')"

docker run --rm --network none huntress-execution-sandbox:dev "curl --version"
```

The verification image's entrypoint is the workspace virtualenv Python, so the
command above is passed directly to Python. The execution sandbox entrypoint is
`/bin/sh -lc`; its argument is a shell command. Do not treat that as a general
purpose runner for untrusted input. In Huntress, only the fixed argv templates
in the reviewed profile registry are executed.

## Local compose

The lab binds only to loopback:

```bash
docker compose -f docker/docker-compose.dev.yml up lab
# http://127.0.0.1:18080/
```

The lab service mounts only `pyproject.toml`, `uv.lock`, `packages/`, and
`config/` read-only, keeps its virtualenv and uv cache in a tmpfs, and runs
`uv sync --frozen --no-dev` at startup. The first start installs the workspace
into the tmpfs, so expect a short delay. It is still a development fixture: do
not point it at a live target or use it with an untrusted checkout.

Run the verification image with its compose profile:

```bash
docker compose -f docker/docker-compose.dev.yml \
  --profile verification run --rm verification
```

Run the offline sandbox smoke:

```bash
docker compose -f docker/docker-compose.dev.yml \
  --profile sandbox run --rm execution-sandbox
```

## Exegol

The execution sandbox is **not** an Exegol server. Exegol supplies its own
container image and the `exegol-mcp` server exposes exactly one reviewed tool,
`execute_command_in_container(container_name, command)`. Huntress talks to that
MCP endpoint over authenticated HTTP and only sends argv templates from its
profile registry.

To use live Exegol:

```bash
export HUNTRESS_EXEGOL_BACKEND=exegol
export HUNTRESS_EXEGOL_URL=http://127.0.0.1:2187/mcp
export HUNTRESS_EXEGOL_CONTAINER=pentest
export HUNTRESS_EXEGOL_TOKEN="<token-from-exegol-mcp>"
uv run huntress health
```

Keep the token in a secret manager or a protected environment, never in the
image, a compose file, or shell history. The adapter refuses non-loopback and
non-private endpoints unless `HUNTRESS_EXEGOL_ALLOW_REMOTE=true` is set after a
network review.

## Security properties

- The images run as an unprivileged user (`uid 10001`) where possible.
- The root `.dockerignore` keeps `.env`, `.huntress`, virtualenvs, and caches
  out of the verification build context.
- The execution sandbox has no Docker socket, host mount, model SDK, or
  credential baked in. The compose service drops all capabilities and has no
  network.
- The verification image installs only the verification dependency closure;
  the import-linter contracts also forbid model SDK imports from scanning,
  verification, and reporting.
- The compose lab is loopback-bound, read-only, selectively mounted, and uses
  `no-new-privileges`. It is a deliberately vulnerable fixture and must never
  be exposed publicly.
- Nothing here authorizes a live target. Scope, approval, budget, and evidence
  controls remain in the operator process and the policy gateway.

## Known limitations

- The images and compose profiles build and smoke-run on the development host,
  but they are not part of `make check`. Build them in CI or on a dedicated
  build host before relying on them for a release.
- The execution sandbox installs only `curl`, `dig`, `nmap`, and `jq`. Profiles
  that need `whatweb`, `nuclei`, or another tool require an explicit image
  change, a profile-registry review, parser/oracle tests, and a threat-model
  update. Do not add a general shell escape or arbitrary package installation
  at runtime.
- The images are not pinned by digest. Pin base images and scan them before
  production use.
- The lab service is development-only: it installs dependencies at startup and
  is not hardened as a production web service.
