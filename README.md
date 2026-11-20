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
│  │ MCP Tool Server (mcp_server.py)                          │  │
│  │ • write_file(path, content)  [Path-jailed to /workspace] │  │
│  │ • read_file(path)            [Line-numbered output]      │  │
│  │ • compile_and_test()         [Deterministic gcc + run]   │  │
│  │ • git_diff()                 [Clean patch for Critic]    │  │
│  └──────────────────────────────────────────────────────────┘  │
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
python3 orchestrator.py

# Or pass any custom C or Kotlin systems task
python3 orchestrator.py "Create ringbuf.h and ringbuf.c implementing a thread-safe bounded ring buffer using pthread_mutex_t and pthread_cond_t. Create test_ringbuf.c verifying total items and sum checksum."
```

## Hardware & Memory Telemetry (Apple Silicon)
Tested on a **2025 MacBook Air (24GB Unified Memory)**:
* **`qwen3:8b` (~5.2 GB footprint):** Runs 100% on Metal GPU with zero SSD swap pressure, completing multi-file C generation, compilation, and Critic verification in 2 Coder turns.
* **Context Sizing:** Configured for `8192`–`16384` token context windows to hold full source diffs and compiler logs without exceeding unified memory ceilings.

## Roadmap
* [x] Zero-dependency MCP `stdio` JSON-RPC 2.0 server with path-jail isolation
* [x] Fresh-context Critic agent auditing `git diff` + deterministic exit codes
* [x] Live token streaming & CLI task parameterization
* [ ] Containerized Linux execution backend (Colima / Docker / gVisor)
* [ ] Native on-device Android NDK (`llama.cpp`) local agent port
