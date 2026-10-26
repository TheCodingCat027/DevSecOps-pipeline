# Vulnerable Demo App — Dockerfile
#
# ⚠️  WARNING: THIS DOCKERFILE IS INTENTIONALLY INSECURE FOR EDUCATIONAL PURPOSES.
# ⚠️  DO NOT BUILD AND RUN IN ANY ENVIRONMENT CONNECTED TO A NETWORK.
# ⚠️  See demo-app/README.md for full safety warnings.
#
# Planted vulnerabilities:
#   V4 — No USER instruction → container runs as root (detected by Hadolint DL3002 / Checkov)
#   V5 — Unpinned / major-only base image tag (detected by Hadolint DL3007)
#   V8 — No HEALTHCHECK instruction (detected by Checkov CKV_DOCKER_2)

# V5: Using major-only tag 'python:3.9' — no digest or patch-level pin.
#     An updated image could introduce unvetted changes or new CVEs on each build.
FROM python:3.9

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# V4: No USER instruction — the process runs as root inside the container.
#     Root inside the container has elevated privileges if the container is compromised.

# V8: No HEALTHCHECK — the orchestrator cannot detect application failures.

EXPOSE 5000

CMD ["python", "app.py"]
