# syntax=docker/dockerfile:1.7
#
# VibeGuard Docker image.
#
# Build from the repository root:
#
#     docker build -t vibeguard:dev .
#
# Run against a mounted source tree:
#
#     docker run --rm -v "$PWD:/scan:ro" vibeguard:dev scan --path /scan
#
# See docs/docker.md for the full guide.

FROM python:3.12-slim AS build

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY vibeguard ./vibeguard

# Build the wheel without dev extras so the runtime layer pulls only the
# runtime dependency set declared in pyproject.toml.
RUN pip install --no-cache-dir build \
    && python -m build --wheel --outdir /wheels


FROM python:3.12-slim AS runtime

ARG VIBEGUARD_VERSION=0.6.0

LABEL org.opencontainers.image.title="VibeGuard" \
      org.opencontainers.image.description="Deterministic pre-merge safety gate for AI-generated code." \
      org.opencontainers.image.source="https://github.com/dgenio/vibeguard" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VIBEGUARD_VERSION}"

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY --from=build /wheels/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl \
    && rm -f /tmp/*.whl \
    && useradd --create-home --uid 1000 --shell /usr/sbin/nologin vibeguard

USER vibeguard
WORKDIR /scan

ENTRYPOINT ["vibeguard"]
CMD ["--help"]
