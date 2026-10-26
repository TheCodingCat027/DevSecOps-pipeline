"""
config.py — Application configuration for the VULNERABLE demo app.

⚠️  WARNING: THIS FILE IS INTENTIONALLY INSECURE FOR EDUCATIONAL PURPOSES ONLY.
⚠️  The credentials below are FAKE / SYNTHETIC values that match the AWS key pattern
    but are NOT real credentials and are NOT associated with any real AWS account.
⚠️  This file MUST NEVER be deployed or exposed to a network.
⚠️  See demo-app/README.md for full safety warnings.

Vulnerability V1: Hardcoded fake AWS credentials (detected by Gitleaks).
Expected rule: aws-access-token / aws-secret-access-key
"""

# V1 — Hardcoded fake AWS credentials (intentionally planted for Gitleaks demo)
# These values are FAKE. They follow the AWS pattern (AKIA + 16 uppercase alphanums)
# but are NOT real credentials. They are planted here purely for scanner testing.
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7FAKEKEY"       # noqa: S105 — fake, for scanner demo
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/FAKESECRETKEYFORTEST"  # noqa: S105 — fake

AWS_REGION = "us-east-1"
S3_BUCKET = "demo-app-uploads"

# Application settings
SECRET_KEY = "dev-secret-key-not-for-production"  # noqa: S105 — insecure, intentional
DATABASE_PATH = "demo.db"
