# Deterministic verification image.
#
# It installs only the verification dependency closure. The reasoning package
# and model SDKs are not installed, and no model or Exegol credentials are
# copied into the image.
FROM python:3.12-slim AS base

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Copy the workspace metadata and package sources. `uv sync --package` installs
# only huntress-verification and its dependency closure.
COPY pyproject.toml uv.lock ./
COPY packages ./packages

RUN uv sync --package huntress-verification --no-dev --frozen \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin hunter \
    && chown -R hunter:hunter /app

USER hunter

# Fail the build if the deterministic verification package cannot be imported.
# Use the synced virtualenv directly so runtime does not need `uv`, a writable
# cache, or network access.
RUN .venv/bin/python -c "import huntress_verification; print('verification image ready')"

ENTRYPOINT ["/app/.venv/bin/python"]
