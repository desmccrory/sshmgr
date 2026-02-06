# syntax=docker/dockerfile:1

# -----------------------------------------------------------------------------
# Stage 1: Build
# -----------------------------------------------------------------------------
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY pyproject.toml README.md ./
RUN pip install --no-cache-dir build wheel \
    && pip wheel --no-cache-dir --wheel-dir /wheels -e .

# -----------------------------------------------------------------------------
# Stage 2: Runtime
# -----------------------------------------------------------------------------
FROM python:3.11-slim AS runtime

# Security: Run as non-root user
RUN groupadd --gid 1000 sshmgr \
    && useradd --uid 1000 --gid sshmgr --shell /bin/bash --create-home sshmgr

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    libpq5 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy wheels and install
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl \
    && rm -rf /wheels

# Copy application code
COPY --chown=sshmgr:sshmgr src/ /app/src/
COPY --chown=sshmgr:sshmgr pyproject.toml README.md /app/

# Install the application
RUN pip install --no-cache-dir -e .

# Create directory for credentials (if needed for CLI)
RUN mkdir -p /home/sshmgr/.sshmgr && chown sshmgr:sshmgr /home/sshmgr/.sshmgr

# Switch to non-root user
USER sshmgr

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SSHMGR_API_HOST=0.0.0.0 \
    SSHMGR_API_PORT=8000 \
    SSHMGR_LOG_FORMAT=json

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/api/v1/health').raise_for_status()"

# Default command
CMD ["python", "-m", "uvicorn", "sshmgr.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
