# Phase 1 baseline. P3 hardens this file in Phase 3.
#
# Fixed Dockerfile — addresses V4, V5, V8:
#   V4 fix: Non-root USER instruction added
#   V5 fix: Pinned base image tag to specific patch version
#   V8 fix: HEALTHCHECK instruction added

# V5 fix: Pinned to specific slim patch version
FROM python:3.12.4-slim

WORKDIR /app

# Install deps first (layer cache optimization)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# V4 fix: Create and switch to a non-root user
RUN useradd -r -u 1001 -g root appuser && \
    chown -R appuser:root /app
USER appuser

EXPOSE 5000

# V8 fix: Add HEALTHCHECK
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')" || exit 1

CMD ["python", "app.py"]
