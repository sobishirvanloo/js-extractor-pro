# syntax=docker/dockerfile:1
#
# js-extractor-pro — self-contained image. Everything the core needs is baked
# in, so the only prerequisite on the host is Docker itself.
#
#   docker build -t js-extractor .
#   docker run --rm -v "$PWD/out:/work" js-extractor https://example.com \
#       --all-analysis --report
#
# Output lands in ./out on the host (mounted at /work, the working dir, which
# is where the default --output-dir ./js_output resolves).
#
# Included: all static + network analysis (endpoints, params, secrets, DOM,
# CVE/OSV, GraphQL, config, replay, source-intel, dependency-confusion, wayback).
# NOT included: the headless browser (--dynamic) and the external crawler
# binaries (katana/gau/httpx/retire/semgrep/wappalyzer) — see Dockerfile.full.

FROM python:3.12-slim

LABEL org.opencontainers.image.title="js-extractor-pro" \
      org.opencontainers.image.description="Extract, beautify and analyze all JavaScript from a web page (recon/pentest tool)." \
      org.opencontainers.image.source="https://github.com/sobishirvanloo/js-extractor-pro" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install the package (and its pinned core deps) from source. Build isolation
# pulls a modern setuptools for the dynamic version; nothing is left behind.
WORKDIR /src
COPY pyproject.toml README.md ./
COPY js_extractor ./js_extractor
RUN pip install . \
    && mkdir -p /work && chmod 777 /work

# Recon shouldn't need root; /work is world-writable so `docker run --user
# "$(id -u):$(id -g)"` works too and keeps host output files owned by you.
WORKDIR /work
ENTRYPOINT ["js-extractor"]
CMD ["--help"]
