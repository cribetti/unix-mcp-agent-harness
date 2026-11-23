# AGENTS.md — `unix-mcp-agent-harness`

Project instructions and architectural reference for AI agents operating in this repository.

## 1. Architecture Overview

`unix-mcp-agent-harness` is a local, systems-engineered Coder + Critic agent harness built on two zero-framework Python components:

- **`orchestrator.py` (Dual-Agent Loop & OpenAI-Compatible Client):**
  - Connects to a local Ollama endpoint (`http://localhost:11434/v1` by default; `qwen3:8b` default, also supports `qwen2.5-coder:7b`).
  - Streams responses live with a 1-second ticking heartbeat (`threading.Thread`) and `max_tokens=4096`.
  - Supports both native OpenAI `delta.tool_calls` and raw JSON tool-call lines emitted in `msg.content` (`extract_fallback_tool_calls`).
  - **Workspace Modes:**
    - Clean-room mode (default when `--workspace` is omitted): wipes and re-initializes `./workspace` with a fresh git repo (`init_workspace`).
    - External repository mode (`--workspace <path>`): preserves the target repository without wiping and forwards `--workspace` to `mcp_server.py`.
    - Automatically loads `AGENTS.md` from the target workspace root into both the Coder and Critic system prompts.
  - **Deterministic Critic Gate (`run_critic`):**
    - Triggered whenever `compile_and_test` returns `EXIT_CODE: 0`.
    - Runs in a fresh context (`temperature=0.0`) auditing `SPEC`, `TEST OUTPUT` (`compile_and_test`), and `GIT DIFF` (`git_diff`).
    - Capped at `2` Critic rejections before halting cleanly.

- **`mcp_server.py` (v0.2.0 — JSON-RPC 2.0 `stdio` MCP Server):**
  - Exposes `unix-sandbox-mcp` (`protocolVersion: 2024-11-05`) over `stdin`/`stdout`.
  - Spawned as a subprocess by `MCPClient` in `orchestrator.py`.

- **`rlvr_mlx.py` (Layer 4 RLVR Dataset Exporter & Apple MLX LoRA Runner):**
  - Reads Critic-approved, `EXIT_CODE: 0` runs logged to `trajectories.jsonl` by `orchestrator.py` (`--trajectories`).
  - Exports normalized `{"messages": [...]}` splits (`mlx_data/train.jsonl`, `mlx_data/valid.jsonl`), automatically unloads cached Ollama models (`ollama stop`) and passes `--grad-checkpoint` to `python -m mlx_lm lora` (`--train`, auto-clamping `--batch-size`), fuses adapters (`--fuse`), and exports `.gguf` (`--export-gguf`) via `llama.cpp/convert_hf_to_gguf.py`.

- **`eval.py` (Held-Out Evaluation Harness):**
  - Benchmarks one or more Ollama models (`--models`) across a 6-task held-out C/Kotlin suite (or `--tasks-file`) without polluting `trajectories.jsonl`, outputting pass rate, average turns, and `eval_results.json`.

## 2. Path-Jail Security Rules

All filesystem tools in `mcp_server.py` are strictly confined to `WORKSPACE`:

- **Workspace Resolution (`resolve_workspace`):** Reads `--workspace <path>` (or `MCP_WORKSPACE` env var, defaulting to `./workspace`) and canonicalizes it via `os.path.realpath(os.path.abspath(...))`.
- **Symlink-Safe Path Jail (`safe_path`):**
  - Resolves the full candidate path via `os.path.realpath(candidate)` (covering both parent directories and leaf symlinks, while supporting non-existent target files for `write_file`).
  - Enforces `os.path.commonpath([WORKSPACE, target]) == WORKSPACE`.
  - Any `../` traversal or symlink pointing outside `WORKSPACE` raises `ValueError("Access denied: '...' escapes workspace")`.
- **Directory Pruning (`PRUNE_DIRS`):** `find_files` and `grep_search` skip `.git`, `.gradle`, `build`, `.idea`, `.cxx`, `captures`, `__pycache__`, and `node_modules`.
- **Kotlin Sanitization (`sanitize_kotlin`):** `write_file` and `edit_file` strip `import kotlin.test.*` lines from `.kt` files so standalone `kotlinc` + `assert(condition)` runs without missing-test-dependency errors.

## 3. MCP Tool Schemas (`mcp_server.py`)

| Tool | Arguments | Description |
| :--- | :--- | :--- |
| `find_files` | `pattern?: string` (default `"*"`), `max_results?: integer` (default `100`) | Lists workspace-relative files matching a glob, excluding `PRUNE_DIRS`. |
| `grep_search` | `query: string` (required), `path?: string` (default `"."`), `max_results?: integer` (default `60`) | Regex/substring search via `rg` (with Python fallback) returning `path:line:content` (lines truncated at 240 chars). |
| `read_file` | `path: string` (required), `start_line?: integer`, `end_line?: integer` | Line-numbered file reader with optional 1-based inclusive line window and 7,000-char truncation. |
| `edit_file` | `path: string` (required), `old_str: string` (required), `new_str: string` (required) | Surgical exact-match replacement; requires unique match in file (returns line numbers on duplicates) and previews edited context. |
| `write_file` | `path: string` (required), `content: string` (required) | Creates or overwrites a file inside `WORKSPACE` (auto-creating parent directories). |
| `compile_and_test` | *(none)* | Auto-detects project type in priority order: (1) `./gradlew testDebugUnitTest --stacktrace` (180s timeout), (2) `kotlinc` + `java -ea MainKt` (45s timeout), (3) `gcc -O2 -g -Wall -pthread *.c -o test_app && ./test_app` (30s timeout). Output truncated head+tail at 7,500 chars. |
| `git_diff` | *(none)* | Runs `git add -N` on source globs (`.kt`, `.kts`, `.java`, `.c`, `.cpp`, `.h`, `.hpp`, `.xml`, `.gradle`, `.properties`, `.md`) and returns `git diff HEAD` excluding `build/` and `.gradle/` (10,000-char cap). |

## 4. Verification Commands

Run from the `unix-mcp-agent-harness/` directory (using the parent `../.venv` Python environment):

```bash
# 1. Fast unit & MCP stdio test suite (includes py_compile, initialize, tools/list, path-jail, and AGENTS.md)
../.venv/bin/python -m unittest test_harness.py -v

# 2. CLI flags check
../.venv/bin/python orchestrator.py --help

# 3. MCP server JSON-RPC 2.0 stdio smoke test (initialize + tools/list + path-jail check)
printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"../../etc/passwd"}}}\n' | ../.venv/bin/python mcp_server.py --workspace ./workspace

# 4. Run against an external repository (non-destructive) with a task string or file
../.venv/bin/python orchestrator.py --workspace /path/to/repo --task /path/to/task.md --model qwen2.5-coder:7b
```
