# -------------------------
# Builder stage
# -------------------------
  ARG TARGETPLATFORM=linux/amd64
  FROM --platform=${TARGETPLATFORM} ghcr.io/astral-sh/uv:python3.13-bookworm-slim AS builder

  ARG APP_HOME=/app
  ENV APP_HOME=${APP_HOME} \
      VENV_PATH="${APP_HOME}/.venv"
  WORKDIR ${APP_HOME}
  
  ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=0
  ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
  
  # Build deps
  RUN apt-get update && apt-get install --no-install-recommends -y \
      build-essential \
      libpq-dev \
      gettext \
    && rm -rf /var/lib/apt/lists/*
  
  # Use uv to install dependencies (cache mounts speed rebuilds)
  RUN --mount=type=cache,target=/root/.cache/uv \
      --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
      --mount=type=bind,source=uv.lock,target=uv.lock:rw \
      uv sync --no-install-project
  
  # Copy source (after deps to leverage cache)
  COPY . ${APP_HOME}
  
  # Install project and dependencies into .venv (uv sync should create .venv)
  RUN --mount=type=cache,target=/root/.cache/uv \
      --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
      --mount=type=bind,source=uv.lock,target=uv.lock:rw \
      uv sync
  
# -------------------------
# Runtime stage
# -------------------------
  ARG TARGETPLATFORM=linux/amd64
  FROM --platform=${TARGETPLATFORM} python:3.13-slim-bookworm AS runtime
  
  ARG APP_HOME=/app
  ENV APP_HOME=${APP_HOME} \
      VENV_PATH="${APP_HOME}/.venv"
  WORKDIR ${APP_HOME}
  
  ENV PYTHONDONTWRITEBYTECODE=1 \
      PYTHONUNBUFFERED=1 \
      PATH="${VENV_PATH}/bin:${PATH}"
  
  # Runtime-only deps
  RUN apt-get update && apt-get install --no-install-recommends -y \
      libpq5 \
      postgresql-client \
    && rm -rf /var/lib/apt/lists/*
  
  # Create non-root user
  RUN useradd --create-home --shell /bin/bash appuser
  # copy from builder
  COPY --from=builder ${APP_HOME} ${APP_HOME}
  RUN chown -R appuser:appuser ${APP_HOME} && \
      chmod +x ${APP_HOME}/entrypoint.sh
  
  USER appuser
  WORKDIR ${APP_HOME}
  
  # Expose port (optional)
  EXPOSE 8000
  
  # Use an entrypoint script to run migrations/wait-for-db if desired/ run guinicorn
  # CMD is handled by entrypoint.sh which will use default gunicorn if no CMD provided
  ENTRYPOINT ["/app/entrypoint.sh"]
  