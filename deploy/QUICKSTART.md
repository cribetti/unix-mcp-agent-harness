# Enterprise VPC Quickstart (< 5 Minutes)

Spin up the hardened `unix-mcp-agent-harness` sandbox inside your corporate VPC or air-gapped build node, verify sandbox isolation offline (`network_mode: none`), route inference to your approved LLM endpoint, and verify the tamper-evident SHA-256 compliance audit log.

---

## 1. Prerequisites (30 seconds)
- Docker Engine `24+` with `docker compose` v2
- A target repository on the host (e.g. `export TARGET_WORKSPACE=/abs/path/to/repo`, or use `../workspace`)

Create the local workspace and compliance log directory from `unix-mcp-agent-harness/deploy`:

```bash
cd unix-mcp-agent-harness/deploy
mkdir -p ../workspace logs && chmod 777 logs
```

*(In production, `chown 10001:10001 logs && chmod 750 logs` locks the audit directory strictly to container UID `10001`.)*

---

## 2. Build & Self-Verify the Air-Gapped Container (`network_mode: none`) (60 seconds)

The default `docker-compose.yml` enforces `user: "10001:10001"`, `read_only: true`, `network_mode: none`, `cap_drop: [ALL]`, `no-new-privileges:true`, and a read-only `/workspace` mount:

```bash
docker compose build agent-sandbox

# Run the built-in red-team & Phase 3 verification suites inside the air-gapped container
docker compose run --rm --entrypoint python agent-sandbox -m unittest test_redteam.py test_phase3.py test_harness.py -v
```

Expected output: every path-traversal, symlink-escape, `.env`/secret-isolation, command-injection, provider-routing, and audit-chain integrity test passes with `OK` under `network_mode: none`.

---

## 3. Configure Your LLM Provider (Zero Code Changes)

### Option A — Enterprise Cloud / VPC Endpoint (Bedrock, Vertex, Azure, vLLM, OpenRouter)
Export the four model-agnostic environment variables (or copy `../config.example.yaml` to `../config.yaml` and set `LLM_CONFIG=/app/config.yaml`):

```bash
# Example 1: Self-hosted vLLM inside corporate VPC
export LLM_PROVIDER=vllm
export LLM_BASE_URL=http://vllm.internal.vpc:8000/v1
export LLM_API_KEY=EMPTY
export LLM_MODEL=Qwen/Qwen2.5-Coder-32B-Instruct

# Example 2: AWS Bedrock (via Bedrock Access Gateway / LiteLLM VPC proxy)
export LLM_PROVIDER=bedrock
export LLM_BASE_URL=https://bedrock-gateway.internal.vpc/v1
export LLM_API_KEY="$BEDROCK_GATEWAY_TOKEN"
export LLM_MODEL=anthropic.claude-3-5-sonnet-20241022-v2:0

# Example 3: GCP Vertex AI OpenAI-compatible endpoint
export LLM_PROVIDER=vertex
export LLM_BASE_URL="https://us-central1-aiplatform.googleapis.com/v1beta1/projects/${GCP_PROJECT_ID}/locations/us-central1/endpoints/openapi"
export LLM_API_KEY="$(gcloud auth print-access-token)"
export LLM_MODEL=google/gemini-2.5-pro

# Example 4: Azure OpenAI Service
export LLM_PROVIDER=azure
export LLM_BASE_URL="https://${AZURE_OPENAI_RESOURCE}.openai.azure.com/openai/v1"
export LLM_API_KEY="$AZURE_OPENAI_API_KEY"
export LLM_MODEL=gpt-4o
```

### Option B — 100% Air-Gapped Local Ollama Sidecar
Use `docker-compose.vpc.yml` (which places `agent-sandbox` and `ollama` on an `internal: true` bridge with zero internet egress):

```bash
docker compose -f docker-compose.vpc.yml --profile local-ollama up -d ollama
docker compose -f docker-compose.vpc.yml exec ollama ollama pull qwen2.5-coder:7b
export LLM_PROVIDER=ollama
export LLM_BASE_URL=http://ollama:11434/v1
export LLM_MODEL=qwen2.5-coder:7b
```

---

## 4. Run a Hardened Autonomous Triage Session (90 seconds)

### Read-Only Audit / Smoke Check (Default)
The default `docker-compose.yml` mounts `${TARGET_WORKSPACE}` as **read-only (`read_only: true`)** with `network_mode: none`:

```bash
TARGET_WORKSPACE=/abs/path/to/repo \
  docker compose run --rm agent-sandbox --workspace /workspace --help
```

### Active Patch & Verify Mode (`:rw` Workspace Mount + VPC/Ollama Network)
To allow the Coder + Critic loop to inspect, patch, run `compile_and_test`, and emit a verified `git_diff` against your target repository:

```bash
# With air-gapped local Ollama sidecar:
docker compose -f docker-compose.vpc.yml run --rm \
  -v /abs/path/to/repo:/workspace:rw \
  agent-sandbox \
  --workspace /workspace \
  --task "Fix the thread-safety bug in TokenBucket.kt and verify all unit tests pass."

# Or with an external corporate VPC endpoint (Bedrock / Vertex / Azure / vLLM):
docker compose run --rm \
  --network bridge \
  -v /abs/path/to/repo:/workspace:rw \
  agent-sandbox \
  --workspace /workspace \
  --task "Fix the thread-safety bug in TokenBucket.kt and verify all unit tests pass."
```

---

## 5. Verify Tamper-Evident Compliance Audit Trail (30 seconds)

Every session writes an append-only, SHA-256 hash-chained `audit.jsonl` file (`prev_hash` → `entry_hash`) capturing `session_start`, `tool_call`, `security_block`, `compile_and_test` verdicts, `git_diff` SHA-256 digest, and `session_end`:

```bash
# Verify cryptographic hash-chain integrity inside the container (exit 0 = untampered, exit 1 = tampered)
docker compose run --rm --entrypoint python agent-sandbox /app/audit_logger.py --verify /var/log/agent-sandbox/audit.jsonl

# Or verify directly on the host using the project virtualenv
../../.venv/bin/python ../audit_logger.py --verify ./logs/audit.jsonl
```

### Built-In Container Hardening Summary
| Control | Setting |
| :--- | :--- |
| Non-root execution | `user: "10001:10001"` (no login shell) |
| Immutable container rootfs | `read_only: true` + `tmpfs` for `/tmp` (`nosuid,nodev`) & `/home/agent` (`noexec,nosuid,nodev`) |
| Network isolation | `network_mode: none` by default (`docker-compose.vpc.yml` for `internal: true` Ollama sidecar) |
| Privilege escalation | `security_opt: ["no-new-privileges:true"]` |
| Linux capabilities | `cap_drop: [ALL]` |
| Resource limits | `cpus: "2.0"`, `mem_limit: 2g`, `pids_limit: 256` |
| Secret redaction | `LLM_API_KEY` and sensitive tokens automatically scrubbed from errors, logs, and `audit.jsonl` |
