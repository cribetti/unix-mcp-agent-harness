# unix-mcp-agent-harness

A zero-framework, systems-engineered autonomous coding harness built on a custom **Model Context Protocol (MCP) JSON-RPC 2.0 `stdio` server** and a dual-agent **Coder + Critic** verification loop—running 100% locally on Apple Silicon via Ollama.

## Why This Exists
Most AI agent demos hand an LLM unrestricted `bash` access and trust the model's self-reported completion. In production environments, probabilistic models require deterministic OS-level guardrails:
1. **Least-Privilege Tool Execution:** Instead of arbitrary shell access, tools run over a custom `stdin`/`stdout` JSON-RPC 2.0 server (`mcp_server.py`) with strict path-jail enforcement (`safe_path`).
2. **Deterministic Verification Gate:** A run cannot succeed until `gcc` compiles cleanly and the test binary exits with `EXIT_CODE: 0`.
3. **Separation of Duties (Coder vs. Critic):** To prevent context drift and shortcut fixes, a separate **Critic** agent receives a clean context window containing only the specification, `git diff`, and test telemetry before approving a change.

## Architecture

```text
┌────────────────────────────────────────────────────────────────┐
│  Orchestrator (orchestrator.py)                                │
│  ┌─────────────────────┐        ┌───────────────────────────┐  │
│  │ Agent 1: CODER      │───────▶│ Agent 2: CRITIC           │  │
│  │ (Local Open-Weights)│        │ (Fresh context + git diff)│  │
│  └──────────┬──────────┘        └─────────────┬─────────────┘  │
│             │  JSON-RPC 2.0 over stdin/stdout │                │
│             ▼                                 ▼                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ MCP Tool Server (mcp_server.py v0.2.0)                   │  │
│  │ • find_files / grep_search   [Pruned repo navigation]    │  │
│  │ • read_file / edit_file      [Paged read + exact patch]  │  │
│  │ • write_file                 [Symlink-safe path jail]    │  │
│  │ • compile_and_test()         [Gradle / kotlinc / gcc]    │  │
│  │ • git_diff()                 [Clean patch for Critic]    │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                │
│  RLVR Loop: Approved runs -> trajectories.jsonl -> rlvr_mlx.py │
└────────────────────────────────────────────────────────────────┘
```

## Quickstart (100% Local on macOS / Linux)

### 1. Prerequisites
* Python 3.11+
* `gcc` or `clang` with `pthread` support
* [Ollama](https://ollama.com) running locally with an open-weights tool-calling model:
  ```bash
  ollama pull qwen3:8b
  ```

### 2. Install & Run
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run the default multi-threaded Kotlin rate-limiter benchmark
python3 orchestrator.py --model qwen2.5-coder:7b

# Run against an existing Android/Gradle, Kotlin, or C repository (non-destructive, auto-loads AGENTS.md)
python3 orchestrator.py --workspace /path/to/repo --task /path/to/task.md --model qwen2.5-coder:7b

# Run the 3-act enterprise showcase (< 60s; add --pace 0.6 for 1080p screen recording — see DEMO_SCRIPT.md)
python3 demo_showcase.py

# Run fast offline Phase 3/4, adversarial red-team, and harness tests (30/30 passing in ~9s)
python3 -m unittest test_phase3.py test_redteam.py test_harness.py -v

# Verify tamper-evident SHA-256 hash chain in a session's audit.jsonl
python3 audit_logger.py --verify audit.jsonl

# Export Critic-approved trajectories for Apple Silicon MLX LoRA fine-tuning
python3 rlvr_mlx.py

# Train 8-bit LoRA, fuse, quantize to Q4_K_M, and write parity-audited Modelfile.custom
python3 rlvr_mlx.py --train --fuse --export-gguf ./custom-qwen-7b-q4_k_m.gguf --outtype f16 --quantize Q4_K_M --write-modelfile ./Modelfile.custom

# Generate 120 deterministic tasks (100 train + 20 eval) and batch-harvest trajectories
python3 generate_tasks.py --count 120 --seed 42 --out generated_tasks.json --eval-out generated_eval_tasks.json --eval-count 20
python3 harvest_rlvr.py --tasks-file generated_tasks.json --limit 20 --model qwen2.5-coder:7b

# Benchmark models on the held-out evaluation suite (auto-runs test_redteam.py --security-gate first)
python3 eval.py --models qwen2.5-coder:7b custom-qwen
```

## Adversarial Red-Team Security Controls (`test_redteam.py`)
Every release and `eval.py` benchmark run is gated by `test_redteam.py` against a live `mcp_server.py` JSON-RPC 2.0 subprocess:
* **Path-Jail & Edge-Case Isolation:** Blocks `../`, URL/double-URL-encoded traversal (`%2e%2e%2f`, `%252e%252e%252f`), null-byte injections (`\x00` / `%00`), absolute/`~` paths, prefix-collision paths (`/tmp/sandbox_evil` vs `/tmp/sandbox`), and symlink/dangling/chained-symlink escapes across all filesystem tools (`read_file`, `write_file`, `edit_file`, `find_files`, `grep_search`).
* **Secret & Credential Exclusion:** Blocks `.env`, `.env.*`, `.git/*`, `.ssh/*`, `.aws/*`, `credentials.*`, `service_account.json`, `keystore.properties`, and private key extensions (`.pem`, `.key`, `.p12`, `.jks`, etc.)—including internal symlinks pointing to secrets.
* **Shell Injection & Socket Containment:** Rejects unexpected `compile_and_test` args, metacharacter/flag filenames, poisoned `gradlew`/`CMakeLists.txt` (`curl`, `wget`, `rm -rf`, `execute_process`, `/dev/tcp/`), raw C/Kotlin socket egress (`socket(AF_INET)`, `java.net.Socket`), and `rg` flag injection (`--`).
* **Prompt-Injection Defense & Structured Security Logging:** `orchestrator.py` converts sandbox denials into non-fatal `SECURITY_BLOCKED` responses and logs every attack as structured JSON (`timestamp`, `tool`, `target`, `reason`, `category`, `workspace`, `sandbox`) to `stderr` and `--security-log`.

## Hardware, Memory & RLVR Benchmark Telemetry (Apple Silicon)
Tested on a **2025 MacBook Air (24GB Unified Memory)**:
* **`qwen3:8b` (~5.2 GB footprint):** Runs 100% on Metal GPU with zero SSD swap pressure, completing multi-file C generation, compilation, and Critic verification in 2 Coder turns.
* **Context Sizing:** Configured for `8192`–`16384` token context windows to hold full source diffs and compiler logs without exceeding unified memory ceilings.
* **Verified Phase 1 `eval.py` Results (36 RLVR trajectories → 8-bit LoRA → `Q4_K_M`, `AUDIT_VERDICT: APPROVED`):**
  * **6-Task Default Suite (`eval_results.json`):** `custom-qwen` **`2/6 (33.3%)`** (`avg_turns=6.0`, `50.6s/task`) vs. base `qwen2.5-coder:7b` **`1/6 (16.7%)`** (`avg_turns=6.33`, `58.1s/task`).
  * **20-Task Held-Out Domain Suite (`eval_results_domain.json`):** `custom-qwen` **`3/20 (15.0%)`** (`avg_turns=8.8`, `102.4s/task`, including held-out C++/CMake JNI fix `ndk_cpp_031_14980c`) vs. base `qwen2.5-coder:7b` **`2/20 (10.0%)`** (`avg_turns=8.65`, `88.9s/task`).

## Roadmap
* [x] Zero-dependency MCP `stdio` JSON-RPC 2.0 server with symlink-safe path-jail isolation (`mcp_server.py`)
* [x] Fresh-context Critic agent auditing `git diff` + deterministic diff/JUnit XML pre-checks (`orchestrator.py`)
* [x] Live token streaming, `--workspace` / `--task` flags, and `AGENTS.md` auto-loading
* [x] Fast offline unit & security test suite (`test_harness.py`, 17/17 passing)
* [x] **Phase 2 Adversarial Red-Team Security Suite (`test_redteam.py`, 7/7 passing) & `eval.py --security-gate`:** Verifies 100% refusal on prompt injections, symlink/dangling/chained-symlink escapes, traversal/null-byte/prefix-collision escapes, `.env`/secret isolation, shell/socket injection, and structured JSON security violation logging (`--security-log`).
* [x] **Phase 3 Model-Agnostic Connector, Compliance Audit Trail & Enterprise VPC Bundle (`providers.py`, `audit_logger.py`, `deploy/`, `test_phase3.py`):** Supports Ollama, vLLM/TGI, Bedrock, Vertex AI, Azure OpenAI, and OpenRouter via `LLM_*` env vars / `config.example.yaml`, emits SHA-256 hash-chained `audit.jsonl` logs (`audit_logger.py --verify`), and ships hardened non-root Docker/Compose deployment manifests (`deploy/QUICKSTART.md`).
* [x] **Phase 4 Client Demo Showcase (`demo_showcase.py`, `DEMO_SCRIPT.md`):** One-command 3-act enterprise demo proving autonomous concurrency bug fix (`EXIT_CODE: 0` + Critic approval), `4/4` live prompt-injection/path-escape blocks, and SHA-256 `audit.jsonl` verification + 1-byte tamper detection.
* [x] Layer 4 RLVR trajectory logging (`trajectories.jsonl`), deterministic task generator (`generate_tasks.py`), batch harvester (`harvest_rlvr.py`), audit packet (`audit_packet.py`), and 8-bit MLX LoRA → `Q4_K_M` GGUF export (`rlvr_mlx.py`, `Modelfile.custom`)
* [x] Held-out evaluation harness (`eval.py`) for comparing base vs. fine-tuned models
* [x] Containerized Linux execution backend (`--sandbox docker` with `--network=none` in `mcp_server.py` / `orchestrator.py`)
* [x] **Milestone 3:** Native on-device Android NDK (`llama.cpp` + JNI + Jetpack Compose) local agent port (`../android-ndk-agent`)
