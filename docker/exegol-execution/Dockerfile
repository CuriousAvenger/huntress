# Minimal isolated execution sandbox for reviewed Exegol profiles.
#
# This image intentionally contains no model SDKs, credentials, Docker socket,
# or host mounts. It is a reference for a narrow tool container. Production
# deployments should prefer the maintained Exegol image and add only the tools
# required by the reviewed profile registry.
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        dnsutils \
        jq \
        nmap \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin hunter \
    && mkdir -p /work \
    && chown hunter:hunter /work

USER hunter
WORKDIR /work

# The MCP server supplies the reviewed argv. This image only provides tools.
ENTRYPOINT ["/bin/sh", "-lc"]
