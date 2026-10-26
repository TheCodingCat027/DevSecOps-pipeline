"""
config.py — Application configuration for the FIXED demo app.

Credentials are read from environment variables, not hard-coded.
See .env.example for the required variable names.

Fix for V1: No hardcoded credentials. Use environment variables or a secrets manager.
"""

import os

# Credentials must be set in the environment (never in source code)
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
S3_BUCKET = os.environ.get("S3_BUCKET", "demo-app-uploads")

# Application settings
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable must be set")

DATABASE_PATH = os.environ.get("DATABASE_PATH", "demo.db")
