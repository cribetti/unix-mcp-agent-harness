# Hardened Enterprise Sandbox Runtime for unix-mcp-agent-harness
# Non-root UID 10001, minimal Debian slim image, no package caches, locked-down defaults.

FROM python:3.12-slim

ARG AGENT_UID=10001
ARG AGENT_GID=10001

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    MCP_WORKSPACE=/workspace \
    MCP_SANDBOX=host \
    MCP_AUDIT_LOG=/var/log/agent-sandbox/audit.jsonl \
    MCP_SECURITY_LOG=/var/log/agent-sandbox/security.jsonl \
    LLM_PROVIDER=ollama \
    LLM_BASE_URL=http://ollama:11434/v1 \
    LLM_MODEL=qwen2.5-coder:7b

# Install minimal build/search toolchain and purge apt caches
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        cmake \
        g++ \
        gcc \
        git \
        make \
        ripgrep \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Create unprivileged service account (no login shell, fixed UID/GID)
RUN groupadd --gid "${AGENT_GID}" agent \
    && useradd --uid "${AGENT_UID}" --gid "${AGENT_GID}" --create-home --home-dir /home/agent --shell /usr/sbin/nologin agent \
    && mkdir -p /app /workspace /var/log/agent-sandbox \
    && chown -R "${AGENT_UID}:${AGENT_GID}" /app /workspace /var/log/agent-sandbox

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY --chown=10001:10001 \
    mcp_server.py \
    orchestrator.py \
    providers.py \
    audit_logger.py \
    eval.py \
    test_redteam.py \
    test_harness.py \
    test_phase3.py \
    config.example.yaml \
    /app/

# Enforce read-only application code and non-root execution
RUN chmod 0555 /app/*.py && chmod 0444 /app/config.example.yaml

USER 10001:10001

HEALTHCHECK --interval=60s --timeout=10s --start-period=5s --retries=2 \
    CMD ["python", "-m", "unittest", "test_redteam.py", "-q"]

ENTRYPOINT ["python", "/app/orchestrator.py"]
CMD ["--help"]
