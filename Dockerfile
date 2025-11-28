# ============================================================================
# Builder stage - Build dependencies and compile Python packages
# ============================================================================
FROM --platform=linux/arm64 ghcr.io/astral-sh/uv:python3.13-bookworm-slim AS builder

ARG APP_HOME=/app
WORKDIR ${APP_HOME}

# Declare load and buffer settings for python + uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=0
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

# Install build dependencies only
RUN apt-get update && apt-get install --no-install-recommends -y \
  build-essential \
  libpq-dev \
  gettext \
  && rm -rf /var/lib/apt/lists/*

# Cache and install dependencies
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    --mount=type=bind,source=uv.lock,target=uv.lock:rw \
    uv sync --no-install-project

# Copy application code
COPY . ${APP_HOME}

# Install project and dependencies
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    --mount=type=bind,source=uv.lock,target=uv.lock:rw \
    uv sync

# ============================================================================
# Runtime stage - Minimal image with only runtime dependencies
# ============================================================================
FROM --platform=linux/arm64 python:3.13-slim-bookworm AS runtime

ARG APP_HOME=/app
WORKDIR ${APP_HOME}

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

# Install only runtime dependencies (not build tools)
RUN apt-get update && apt-get install --no-install-recommends -y \
  # Runtime PostgreSQL client library (not dev package)
  libpq5 \
  # PostgreSQL client tools (for pg_isready in entrypoint)
  postgresql-client \
  # Development tools (for dev environment)
  sudo \
  git \
  bash-completion \
  nano \
  ssh \
  wait-for-it \
  && rm -rf /var/lib/apt/lists/*

# Copy application code
COPY --from=builder ${APP_HOME} ${APP_HOME}

# Set up Python environment
ENV PATH="${APP_HOME}/.venv/bin:$PATH" \
    PYTHONPATH="${APP_HOME}/.venv/lib/python3.13/site-packages"

RUN chmod +x ${APP_HOME}/entrypoint.sh

EXPOSE 8000


