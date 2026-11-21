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

    def __init__(self, script_path: str):
        self.proc = subprocess.Popen(
            [sys.executable, script_path],
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


def run_critic(client: OpenAI, model: str, mcp: MCPClient, spec: str) -> tuple[bool, str]:
    """Fresh-context Critic agent that audits git diff + deterministic build/test execution."""
    diff = mcp.call_tool("git_diff", {})
    test_out = mcp.call_tool("compile_and_test", {})

    if "EXIT_CODE: 0" not in test_out:
        return False, f"Build/Test failed:\n{test_out}"

    critic_prompt = (
        f"Audit this implementation strictly against the spec.\nSPEC: {spec}\n\n"
        f"TEST OUTPUT:\n{test_out}\n\nGIT DIFF:\n{diff}\n\n"
        "PASS CRITERIA (approve immediately if ALL 4 are true):\n"
        "1. TEST OUTPUT shows EXIT_CODE: 0 with zero exceptions or AssertionErrors in STDERR.\n"
        "2. Uses the required synchronization primitive from SPEC (e.g., ReentrantLock or pthread_mutex_t).\n"
        "3. Implements the core logic and runs real multi-threaded assertions (not empty stubs).\n"
        "4. Satisfies every explicit requirement in SPEC.\n\n"
        "RULES: Do NOT reject for style, extra edge cases not in SPEC, or suggest refactoring. "
        "Reply starting with 'APPROVED:' if all 4 pass, or 'REJECTED:' with only blocking bugs."
    )

    msg = stream_turn(
        client=client,
        model=model,
        messages=[
            {"role": "system", "content": "You are a strict systems code reviewer."},
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
            '  python3 orchestrator.py --model qwen2.5-coder:7b "Create cache.h and cache.c implementing a thread-safe LRU cache with pthread_mutex_t, plus test_cache.c."\n'
        ),
    )
    parser.add_argument("spec", nargs="?", default=DEFAULT_SPEC, help="Engineering task specification")
    parser.add_argument("--model", default="qwen3:8b", help="Local Ollama model name (default: qwen3:8b)")
    parser.add_argument("--base-url", default="http://localhost:11434/v1", help="OpenAI-compatible endpoint URL")
    parser.add_argument("--max-turns", type=int, default=12, help="Maximum Coder turns before aborting")
    args = parser.parse_args()

    workspace = os.path.abspath("./workspace")
    init_workspace(workspace)

    client = OpenAI(base_url=args.base_url, api_key="ollama", timeout=300.0)
    mcp = MCPClient("mcp_server.py")
    openai_tools = mcp.get_openai_tools()

    messages = [
        {
            "role": "system",
            "content": (
                "You are a systems engineer. Use write_file, read_file, and compile_and_test "
                "via tool calls. Never output code in chat text. For Kotlin tests, use built-in "
                "`assert(condition)` directly and NEVER import `kotlin.test.*`. /no_think"
            ),
        },
        {"role": "user", "content": args.spec},
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
                            print("\n=== [Critic Review] ===", flush=True)
                            approved, feedback = run_critic(client, args.model, mcp, args.spec)
                            if approved:
                                print("\n=== APPROVED BY CRITIC & VERIFIED EXIT 0 ===", flush=True)
                                return
                            critic_rejections += 1
                            if critic_rejections >= 2:
                                print("\n=== [Harness] Critic rejection cap (2) reached — halting cleanly ===", flush=True)
                                return
                            messages.append({"role": "user", "content": f"Critic feedback:\n{feedback}\n/no_think"})
                            break

                        else:
                            out += "\n\nINSTRUCTION: Fix ALL errors listed above across all files in one batch before calling compile_and_test again."
                    messages.append({"role": "tool", "tool_call_id": tc.id, "content": out})

            else:
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
