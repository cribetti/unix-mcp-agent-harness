# AGENTS.md — `unix-mcp-agent-harness`

Project instructions and architectural reference for AI agents operating in this repository.

## 1. Architecture Overview

`unix-mcp-agent-harness` is a local, systems-engineered Coder + Critic agent harness built on two zero-framework Python components:

- **`orchestrator.py` (Dual-Agent Loop & OpenAI-Compatible Client):**
  - Connects to a local Ollama endpoint (`http://localhost:11434/v1` by default; `qwen3:8b` default, also supports `qwen2.5-coder:7b` and `qwen3:14b` with `reasoning_effort="none"` to suppress thinking stalls).
  - Streams responses live with a 1-second ticking heartbeat (`threading.Thread`), `max_tokens=4096`, and consecutive duplicate non-test tool-call guarding.
  - Supports both native OpenAI `delta.tool_calls` and raw JSON tool-call lines emitted in `msg.content` (`extract_fallback_tool_calls`).
  - **Workspace Modes:**
    - Clean-room mode (default when `--workspace` is omitted): wipes and re-initializes `./workspace` with a fresh git repo (`init_workspace`).
    - External repository mode (`--workspace <path>`): preserves the target repository without wiping, injects the initial `find_files('*')` listing into the user prompt, and forwards `--workspace` to `mcp_server.py`.
    - Automatically loads `AGENTS.md` from the target workspace root into both the Coder and Critic system prompts.
  - **Deterministic Critic Gate (`run_critic`):**
    - Triggered whenever `compile_and_test` returns `EXIT_CODE: 0`.
    - Runs in a fresh context (`temperature=0.0`) auditing `SPEC`, `TEST OUTPUT` (`compile_and_test`), and `GIT DIFF` (`git_diff`).
    - Capped at `2` Critic rejections before halting cleanly.

- **`mcp_server.py` (v0.2.0 — JSON-RPC 2.0 `stdio` MCP Server):**
  - Exposes `unix-sandbox-mcp` (`protocolVersion: 2024-11-05`) over `stdin`/`stdout`.
  - Spawned as a subprocess by `MCPClient` in `orchestrator.py`.
  - Supports `--sandbox host` (default) or `--sandbox docker` (`docker run --rm --network=none`) for `compile_and_test`.

- **`rlvr_mlx.py` (Layer 4 RLVR Dataset Exporter & Apple MLX LoRA Runner):**
  - Reads Critic-approved, `EXIT_CODE: 0` runs logged to `trajectories.jsonl` by `orchestrator.py` (`--trajectories`), filtering legacy `"git_diff": "No changes."` rows by default.
  - Preserves structured `tool_calls` and OpenAI `tools` schemas for `chat_template.jinja` parity (`mlx_data/train.jsonl`, `mlx_data/valid.jsonl`), auto-unloads Ollama models (`ollama stop`), trains 8-bit base (`mlx-community/Qwen2.5-Coder-7B-Instruct-8bit`) with `AdamW` (`eps=1e-5`, `max_seq_length=8192`, `--grad-checkpoint`), checks finite weights (`verify_adapter_finite()`), fuses adapters (`--fuse`), exports `.gguf` (`--export-gguf` + `--quantize Q4_K_M` via `llama-quantize`), and writes `Modelfile.custom`.

- **`generate_tasks.py`, `harvest_rlvr.py` & `eval.py` (Task Generation, Batch Harvest & Eval):**
  - `generate_tasks.py` creates deterministic Android/Kotlin/NDK/C and OWASP MASVS task suites (`generated_tasks.json`, `generated_eval_tasks.json`).
  - `harvest_rlvr.py` batch-runs `orchestrator.py` across generated tasks (materializing temp git workspaces when `workspace_files` is present).
  - `eval.py` benchmarks Ollama models (`--models`) across the 6-task default suite or `--tasks-file` without polluting `trajectories.jsonl`, outputting pass rate, average turns, and `eval_results.json`.

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
| `find_files` | `pattern?: string` (default `"*"`), `max_results?: integer` (default `100`) | Lists workspace-relative files matching space/comma-separated globs (falling back to workspace listing on 0 matches), excluding `PRUNE_DIRS`. |
| `grep_search` | `query: string` (required), `path?: string` (default `"."`), `max_results?: integer` (default `60`) | Regex/substring search via `rg` (with Python fallback) returning `path:line:content` (lines truncated at 240 chars). |
| `read_file` | `path: string` (required), `start_line?: integer`, `end_line?: integer` | Line-numbered file reader with optional 1-based inclusive line window and 7,000-char truncation. |
| `edit_file` | `path: string` (required), `old_str: string` (required), `new_str: string` (required) | Surgical exact-match replacement (with unique-indentation fallback); requires unique match and previews edited context. |
| `write_file` | `path: string` (required), `content: string` (required) | Creates or overwrites a file inside `WORKSPACE` (auto-creating parent directories). |
| `compile_and_test` | *(none)* | Auto-detects project type in priority order: (1) `./gradlew testDebugUnitTest --stacktrace` (180s), (2) `CMakeLists.txt` + `cmake`/`ctest` (60s), (3) `kotlinc` + `java -ea MainKt` (45s), (4) `g++ -std=c++17 *.cpp` (30s), (5) `gcc *.c` (30s). Output truncated head+tail at 7,500 chars. |
| `git_diff` | *(none)* | Runs `git add -N` on source globs (`.kt`, `.kts`, `.java`, `.c`, `.cpp`, `.h`, `.hpp`, `.xml`, `.gradle`, `.properties`, `.md`, `CMakeLists.txt`) and returns `git diff HEAD` excluding `build/` and `.gradle/` (10,000-char cap). |

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
