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

# Run fast offline harness & security tests
python3 -m unittest test_harness.py -v

# Export Critic-approved trajectories for Apple Silicon MLX LoRA fine-tuning
python3 rlvr_mlx.py

# Train, fuse, and export a custom .gguf for Android / Ollama
python3 rlvr_mlx.py --model mlx-community/Qwen2.5-Coder-1.5B-Instruct-4bit --train --fuse --export-gguf ./custom-qwen.gguf

# Benchmark models on the held-out evaluation suite
python3 eval.py --models qwen2.5-coder:7b qwen3:8b
```

## Hardware & Memory Telemetry (Apple Silicon)
Tested on a **2025 MacBook Air (24GB Unified Memory)**:
* **`qwen3:8b` (~5.2 GB footprint):** Runs 100% on Metal GPU with zero SSD swap pressure, completing multi-file C generation, compilation, and Critic verification in 2 Coder turns.
* **Context Sizing:** Configured for `8192`–`16384` token context windows to hold full source diffs and compiler logs without exceeding unified memory ceilings.

## Roadmap
* [x] Zero-dependency MCP `stdio` JSON-RPC 2.0 server with symlink-safe path-jail isolation (`mcp_server.py`)
* [x] Fresh-context Critic agent auditing `git diff` + deterministic exit codes (`orchestrator.py`)
* [x] Live token streaming, `--workspace` / `--task` flags, and `AGENTS.md` auto-loading
* [x] Fast offline unit & security test suite (`test_harness.py`)
* [x] Layer 4 RLVR trajectory logging (`trajectories.jsonl`) + Apple MLX LoRA exporter/runner/GGUF export (`rlvr_mlx.py`)
* [x] Held-out evaluation harness (`eval.py`) for comparing base vs. fine-tuned models
* [ ] Containerized Linux execution backend (Colima / Docker / gVisor)
* [x] **Milestone 3:** Native on-device Android NDK (`llama.cpp` + JNI + Jetpack Compose) local agent port (`../android-ndk-agent`)
