# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later

# MockTAXII v1.1.4 - TAXII 2.x server for Cortex Platform and TAXII client testing
#
# Multi-stage build: the builder resolves dependencies with uv, the runtime
# image carries only the resulting virtualenv. No compiler, pip or uv ships in
# the final image. Almost every dependency resolves to a binary wheel; `cpe`,
# pulled in by stix2-validator, is sdist-only, so the builder stage still needs
# to be able to build a pure-Python sdist. Do not add a wheels-only constraint
# to this stage without first checking that.

ARG PYTHON_TAG=3.14-slim-trixie
ARG UV_VERSION=0.12.14

# ---------------------------------------------------------------------------
# Stage 1 - build the virtualenv
# ---------------------------------------------------------------------------
FROM python:${PYTHON_TAG} AS builder

ARG UV_VERSION
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# Pinned so the resolver cannot silently vary between builds
RUN pip install "uv==${UV_VERSION}"

WORKDIR /app

# Dependency layer: only invalidated when the manifest or lock changes
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

# ---------------------------------------------------------------------------
# Stage 2 - test runner (built explicitly with --target tester; never shipped)
# ---------------------------------------------------------------------------
FROM builder AS tester

# Adds the dev dependency group on top of the resolved runtime venv
RUN uv sync --frozen
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH=/app \
    PYTHONUNBUFFERED=1
COPY pyproject.toml uv.lock ./
COPY *.py ./
COPY templates/ ./templates/
COPY assets/ ./assets/
COPY vendor/ ./vendor/
COPY tests/ ./tests/
COPY docker-entrypoint.sh ./
# test_release_security.py asserts the dotenv ignore rules, so the suite needs
# the real file rather than a copy that can drift.
COPY .gitignore ./
CMD ["pytest", "-q"]

# ---------------------------------------------------------------------------
# Stage 3 - runtime
# ---------------------------------------------------------------------------
FROM python:${PYTHON_TAG}

LABEL org.opencontainers.image.title="MockTAXII" \
      org.opencontainers.image.description="TAXII 2.x server for testing threat intelligence integrations, primarily the Palo Alto Networks Cortex Platform (XSIAM, XSOAR)" \
      org.opencontainers.image.source="https://github.com/simonsigre/mocktaxii" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"

# curl backs the HEALTHCHECK; postgresql-client backs pg_isready/psql in the
# entrypoint. Nothing else is needed at runtime.
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        curl \
        postgresql-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Non-root user, created before the virtualenv lands so ownership is right
RUN useradd --create-home --shell /bin/bash app

COPY --from=builder --chown=app:app /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Explicit file list rather than `COPY . .`.
#
# This list is the ONLY thing deciding what ends up in the image. .dockerignore
# keeps the build context small and keeps dotenv files, the repository metadata
# and a host-built virtualenv out of it, but it does not enumerate everything
# in the tree, so a wildcard copy here would bake in whatever it does not name
# - the exact exposure the "production secrets baked into Docker images" fix
# was meant to close. tests/repo_layout_checks.py asserts that the image
# contains only what is listed below.
COPY --chown=app:app *.py ./
COPY --chown=app:app templates/ ./templates/
COPY --chown=app:app assets/ ./assets/
# Third-party libraries, served from /vendor by a blueprint in app.py. Kept
# out of assets/ so that directory holds only first-party files.
COPY --chown=app:app vendor/ ./vendor/

USER app

EXPOSE 5000

ENV PYTHONPATH=/app \
    FLASK_APP=main.py \
    PYTHONUNBUFFERED=1

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -fsS http://localhost:5000/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

# gthread rather than sync: two sync workers serve exactly two concurrent
# requests process-wide, so a third poll queues behind them - including the
# healthcheck. --max-requests recycles workers (there was none, so they ran
# forever). The previous --keep-alive 60 was a no-op: the sync worker ignores it.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", \
     "--worker-class", "gthread", "--workers", "2", "--threads", "4", \
     "--timeout", "120", "--graceful-timeout", "30", \
     "--max-requests", "1000", "--max-requests-jitter", "100", \
     "--access-logfile", "-", \
     "main:app"]
