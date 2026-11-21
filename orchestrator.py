import argparse
import json
import os
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from openai import OpenAI


DEFAULT_SPEC = (
    "Create `RateLimiter.kt` and `Main.kt` implementing a thread-safe token-bucket rate limiter "
    "in Kotlin using `ReentrantLock` (with `try { ... } finally { lock.unlock() }`). "
    "In `Main.kt`, use standard `Thread { ... }` (not ExecutorService) and built-in `assert(condition)` "
    "(do NOT import kotlin.test) to verify burst capacity, refill over time, and 8 concurrent threads, "
    "printing 'ALL TESTS PASSED' at the end."
)


class MCPClient:
    """Lightweight JSON-RPC 2.0 client communicating with mcp_server.py over stdio pipes."""

    def __init__(self, script_path: str, workspace: str | None = None):
        cmd = [sys.executable, script_path]
        if workspace:
            cmd.extend(["--workspace", workspace])
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._id = 0
        self.rpc("initialize", {})

    def rpc(self, method: str, params: dict) -> dict:
        self._id += 1
        payload = {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}
        self.proc.stdin.write(json.dumps(payload) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError("MCP server closed stdout unexpectedly")
        resp = json.loads(line)
        if "error" in resp:
            raise RuntimeError(resp["error"]["message"])
        return resp["result"]

    def get_openai_tools(self) -> list[dict]:
        mcp_tools = self.rpc("tools/list", {})["tools"]
        return [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t["description"],
                    "parameters": t["inputSchema"],
                },
            }
            for t in mcp_tools
        ]

    def call_tool(self, name: str, args: dict) -> str:
        res = self.rpc("tools/call", {"name": name, "arguments": args})
        return res["content"][0]["text"]

    def close(self):
        if self.proc.stdin:
            self.proc.stdin.close()
        if self.proc.stdout:
            self.proc.stdout.close()
        self.proc.terminate()
        self.proc.wait(timeout=2)


def stream_turn(
    client: OpenAI,
    model: str,
    messages: list[dict],
    tools: list[dict] | None = None,
    temp: float = 0.1,
):
    """Stream tokens live to stdout with a 1-second ticking heartbeat and token cap."""
    t0 = time.perf_counter()
    got_output = threading.Event()

    def heartbeat():
        while not got_output.wait(1.0):
            sys.stdout.write(f"\r  [Ollama thinking / building JSON... {time.perf_counter() - t0:.0f}s]")
            sys.stdout.flush()

    timer = threading.Thread(target=heartbeat, daemon=True)
    timer.start()

    try:
        stream = client.chat.completions.create(
            model=model,
            messages=messages,
            tools=tools,
            temperature=temp,
            max_tokens=4096,
            stream=True,
        )

        content_parts = []
        tool_acc = {}

        for chunk in stream:
            if not chunk.choices:
                continue
            delta = chunk.choices[0].delta

            if (delta.content or delta.tool_calls) and not got_output.is_set():
                got_output.set()
                sys.stdout.write("\r" + " " * 55 + "\r")
                sys.stdout.flush()

            if delta.content:
                sys.stdout.write(delta.content)
                sys.stdout.flush()
                content_parts.append(delta.content)

            if delta.tool_calls:
                for tc in delta.tool_calls:
                    entry = tool_acc.setdefault(tc.index, {"id": "", "name": "", "args": []})
                    if tc.id:
                        entry["id"] = tc.id
                    if tc.function:
                        if tc.function.name:
                            entry["name"] += tc.function.name
                            print(f"  [Building tool call: {entry['name']}]", flush=True)
                        if tc.function.arguments:
                            entry["args"].append(tc.function.arguments)
    finally:
        got_output.set()

    dt = time.perf_counter() - t0
    print(f"  [Done in {dt:.1f}s]", flush=True)

    tool_calls = [
        SimpleNamespace(
            id=tool_acc[idx]["id"] or f"call_{idx}",
            type="function",
            function=SimpleNamespace(
                name=tool_acc[idx]["name"],
                arguments="".join(tool_acc[idx]["args"]),
            ),
        )
        for idx in sorted(tool_acc)
    ]

    return SimpleNamespace(
        role="assistant",
        content="".join(content_parts),
        tool_calls=tool_calls or None,
    )


def init_workspace(workspace: str) -> None:
    os.makedirs(workspace, exist_ok=True)
    subprocess.run(
        "rm -rf * .git && git init -q && git config user.email 'agent@local' && git config user.name 'Agent' && git commit --allow-empty -m 'init' -q",
        shell=True,
        cwd=workspace,
        check=True,
    )


def load_agents_md(workspace: str) -> str:
    """Load AGENTS.md from the target workspace root if present."""
    agents_path = os.path.join(workspace, "AGENTS.md")
    if not os.path.isfile(agents_path):
        return ""
    with open(agents_path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read().strip()
    if len(content) > 12000:
        content = content[:12000] + "\n... [AGENTS.md truncated at 12,000 chars]"
    return content


def resolve_task_spec(task_arg: str | None, positional_spec: str | None) -> str:
    """Resolve task specification from --task (string or file path), positional spec, or DEFAULT_SPEC."""
    if task_arg:
        if os.path.isfile(task_arg):
            with open(task_arg, "r", encoding="utf-8", errors="replace") as f:
                return f.read().strip()
        return task_arg
    if positional_spec:
        return positional_spec
    return DEFAULT_SPEC


def run_critic(
    client: OpenAI,
    model: str,
    mcp: MCPClient,
    spec: str,
    agents_md: str = "",
) -> tuple[bool, str]:
    """Fresh-context Critic agent that audits git diff + deterministic build/test execution."""
    diff = mcp.call_tool("git_diff", {})
    test_out = mcp.call_tool("compile_and_test", {})

    if "EXIT_CODE: 0" not in test_out:
        return False, f"Build/Test failed:\n{test_out}"

    critic_system = "You are a strict systems code reviewer."
    if agents_md:
        critic_system += f"\n\nTarget Repository AGENTS.md:\n{agents_md}"

    critic_prompt = (
        f"Audit this implementation strictly against the spec.\nSPEC: {spec}\n\n"
        f"TEST OUTPUT:\n{test_out}\n\nGIT DIFF:\n{diff}\n\n"
        "PASS CRITERIA (approve immediately if ALL 4 are true):\n"
        "1. TEST OUTPUT shows EXIT_CODE: 0 with zero exceptions or AssertionErrors in STDERR.\n"
        "2. Follows any required synchronization primitives, architecture, or constraints in SPEC and AGENTS.md.\n"
        "3. Implements the core logic and runs real tests/assertions (not empty stubs).\n"
        "4. Satisfies every explicit requirement in SPEC.\n\n"
        "RULES: Do NOT reject for style, extra edge cases not in SPEC, or suggest refactoring. "
        "Reply starting with 'APPROVED:' if all 4 pass, or 'REJECTED:' with only blocking bugs."
    )

    msg = stream_turn(
        client=client,
        model=model,
        messages=[
            {"role": "system", "content": critic_system},
            {"role": "user", "content": critic_prompt},
        ],
        tools=None,
        temp=0.0,
    )
    verdict = (msg.content or "").strip()
    return verdict.startswith("APPROVED:"), verdict

def extract_fallback_tool_calls(content: str | None) -> list[SimpleNamespace] | None:
    """Parse raw JSON tool-call objects if a model emits them in message content."""
    if not content:
        return None
    calls = []
    for idx, line in enumerate(content.strip().splitlines()):
        line = line.strip()
        if line.startswith("{") and '"name"' in line and '"arguments"' in line:
            try:
                obj = json.loads(line)
                if isinstance(obj.get("name"), str) and isinstance(obj.get("arguments"), dict):
                    calls.append(
                        SimpleNamespace(
                            id=f"fallback_call_{idx}",
                            type="function",
                            function=SimpleNamespace(
                                name=obj["name"],
                                arguments=json.dumps(obj["arguments"]),
                            ),
                        )
                    )
            except json.JSONDecodeError:
                pass
    return calls or None

def main():
    parser = argparse.ArgumentParser(
        description="Local MCP Coder + Critic Autonomous Harness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 orchestrator.py\n"
            "  python3 orchestrator.py --model qwen2.5-coder:7b\n"
            "  python3 orchestrator.py --workspace /path/to/android-repo --task task.md --model qwen2.5-coder:7b\n"
            '  python3 orchestrator.py --model qwen2.5-coder:7b "Create cache.h and cache.c implementing a thread-safe LRU cache with pthread_mutex_t, plus test_cache.c."\n'
        ),
    )
    parser.add_argument("spec", nargs="?", default=None, help="Engineering task specification")
    parser.add_argument("--task", default=None, help="Task specification string or path to a spec file")
    parser.add_argument(
        "--workspace",
        default=None,
        help="Target repository path (if omitted, resets clean-room ./workspace)",
    )
    parser.add_argument("--model", default="qwen3:8b", help="Local Ollama model name (default: qwen3:8b)")
    parser.add_argument("--base-url", default="http://localhost:11434/v1", help="OpenAI-compatible endpoint URL")
    parser.add_argument("--max-turns", type=int, default=12, help="Maximum Coder turns before aborting")
    args = parser.parse_args()

    spec = resolve_task_spec(args.task, args.spec)
    is_external_workspace = args.workspace is not None

    if is_external_workspace:
        workspace = os.path.realpath(os.path.abspath(args.workspace))
        if not os.path.isdir(workspace):
            print(f"ERROR: Workspace directory does not exist: {workspace}", file=sys.stderr)
            sys.exit(1)
        print(f"[Harness] Using existing workspace (no wipe): {workspace}", flush=True)
    else:
        workspace = os.path.abspath("./workspace")
        init_workspace(workspace)

    agents_md = load_agents_md(workspace)
    if agents_md:
        print(f"[Harness] Loaded AGENTS.md ({len(agents_md)} chars) from {workspace}", flush=True)

    print(f"\n=== [Task] ===\n{spec}", flush=True)

    coder_system = (
        "You are a systems engineer. Use tool calls only—never output code in chat text. "
        "In existing or multi-file repositories, first navigate with `find_files`, `grep_search`, "
        "and paged `read_file` (`start_line`/`end_line`) to inspect relevant files, then apply "
        "surgical patches with `edit_file` (or create new files with `write_file`) before running "
        "`compile_and_test`. For standalone Kotlin tests, use built-in `assert(condition)` directly "
        "and NEVER import `kotlin.test.*`. /no_think"
    )
    if agents_md:
        coder_system += f"\n\nTarget Repository AGENTS.md:\n{agents_md}"

    mcp_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mcp_server.py")
    client = OpenAI(base_url=args.base_url, api_key="ollama", timeout=300.0)
    mcp = MCPClient(mcp_script, workspace=workspace)
    openai_tools = mcp.get_openai_tools()

    messages = [
        {"role": "system", "content": coder_system},
        {"role": "user", "content": spec},
    ]

    try:
        critic_rejections = 0
        for turn in range(args.max_turns):
            print(f"\n=== [Coder Turn {turn+1} | {args.model}] ===", flush=True)
            msg = stream_turn(client, args.model, messages, tools=openai_tools, temp=0.1)
            if not msg.tool_calls:
                msg.tool_calls = extract_fallback_tool_calls(msg.content)

            messages.append({
                "role": "assistant",
                "content": msg.content,
                **({"tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                    }
                    for tc in msg.tool_calls
                ]} if msg.tool_calls else {}),
            })

            if msg.tool_calls:
                for tc in msg.tool_calls:
                    call_args = json.loads(tc.function.arguments)
                    print(f"  -> MCP {tc.function.name}({list(call_args.keys())})", flush=True)
                    out = mcp.call_tool(tc.function.name, call_args)
                    if tc.function.name == "compile_and_test":
                        print("\n".join(f"     {line}" for line in out.splitlines()[:25]), flush=True)
                        if "EXIT_CODE: 0" in out:
                            messages.append({"role": "tool", "tool_call_id": tc.id, "content": out})
                            print("\n=== [Critic Review] ===", flush=True)
                            approved, feedback = run_critic(
                                client, args.model, mcp, spec, agents_md=agents_md
                            )
                            if approved:
                                print("\n=== APPROVED BY CRITIC & VERIFIED EXIT 0 ===", flush=True)
                                return
                            critic_rejections += 1
                            if critic_rejections >= 2:
                                print("\n=== [Harness] Critic rejection cap (2) reached — halting cleanly ===", flush=True)
                                return
                            messages.append({"role": "user", "content": f"Critic feedback:\n{feedback}\n/no_think"})
                            break

                        out += "\n\nINSTRUCTION: Fix ALL errors listed above across all files in one batch before calling compile_and_test again."
                    messages.append({"role": "tool", "tool_call_id": tc.id, "content": out})

            else:
                if is_external_workspace:
                    print("[Harness] Nudging Coder to use MCP tools...", flush=True)
                    messages.append({
                        "role": "user",
                        "content": (
                            "Use `find_files`, `grep_search`, `read_file`, `edit_file`, or `compile_and_test` "
                            "via tool calls to inspect, modify, and verify the repository. /no_think"
                        ),
                    })
                    continue

                src_files = [f for f in os.listdir(workspace) if f.endswith((".c", ".kt"))]
                if not src_files:
                    print("[Harness] No source files written yet — nudging Coder to use write_file...", flush=True)
                    messages.append({
                        "role": "user",
                        "content": "Call `write_file` right now to create the source and test files. /no_think",
                    })
                    continue

                print("[Harness] Nudging Coder to run compile_and_test...", flush=True)
                messages.append({
                    "role": "user",
                    "content": "Call `compile_and_test` now to verify your changes. /no_think",
                })

    finally:
        mcp.close()


if __name__ == "__main__":
    main()
