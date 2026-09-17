# syntax=docker/dockerfile:1

# ── AICore API ────────────────────────────────────────────────────────────────
# Build context: repository root.
#   docker build -f apps/api/Dockerfile .
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Dependencies first (layer caching), then the source.
COPY apps/api/pyproject.toml ./pyproject.toml
COPY apps/api/src ./src
RUN pip install --no-cache-dir . && \
    groupadd --system --gid 10001 aicore && \
    useradd --system --uid 10001 --gid aicore --no-create-home aicore

USER aicore

EXPOSE 8000

# Liveness probe used by Compose/orchestrators; /health does not touch the database.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).status == 200 else 1)"

CMD ["python", "-m", "uvicorn", "aicore_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
