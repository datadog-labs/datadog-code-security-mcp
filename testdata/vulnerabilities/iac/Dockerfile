# Dockerfile with security misconfigurations
# This file demonstrates common Dockerfile security issues for E2E testing

# VULNERABLE: Using latest tag (non-deterministic builds)
FROM ubuntu:latest

# VULNERABLE: Running as root (no USER instruction to switch)

# VULNERABLE: Installing packages without pinning versions
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    python3 \
    nodejs \
    && rm -rf /var/lib/apt/lists/*

# VULNERABLE: Using ADD instead of COPY (ADD can fetch remote URLs and auto-extract)
ADD https://example.com/app.tar.gz /opt/app/

# VULNERABLE: Hardcoded secrets in environment variables
ENV DATABASE_PASSWORD=mysecretpassword123
ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
ENV API_TOKEN=tok_live_abcdef1234567890

# VULNERABLE: Exposing SSH port
EXPOSE 22
EXPOSE 80
EXPOSE 443

# VULNERABLE: Using sudo/su in RUN
RUN chmod 777 /tmp

# VULNERABLE: Copying entire context (may include .env, .git, etc.)
COPY . /app

WORKDIR /app

# VULNERABLE: Running as root (no USER instruction)
CMD ["python3", "app.py"]
