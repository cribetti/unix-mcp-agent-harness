import json
import os
import subprocess
import sys

WORKSPACE = os.path.abspath("./workspace")
os.makedirs(WORKSPACE, exist_ok=True)


def safe_path(rel_path: str) -> str:
    """Enforce path-jail security so tools cannot escape WORKSPACE."""
    target = os.path.abspath(os.path.join(WORKSPACE, rel_path))
    if not target.startswith(WORKSPACE + os.sep) and target != WORKSPACE:
        raise ValueError(f"Access denied: {rel_path} escapes workspace")
    return target


TOOLS = [
    {
        "name": "write_file",
        "description": "Write full content to a file inside workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string"},
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "read_file",
        "description": "Read a file from workspace with line numbers.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "compile_and_test",
        "description": "Compile C files in workspace with gcc -Wall -pthread and run ./test_app.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "git_diff",
        "description": "Return current git diff and status of workspace.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def call_tool(name: str, args: dict) -> str:
    if name == "write_file":
        p = safe_path(args["path"])
        with open(p, "w", encoding="utf-8") as f:
            f.write(args["content"])
        return f"OK: wrote {len(args['content'])} bytes to {args['path']}"

    if name == "read_file":
        p = safe_path(args["path"])
        if not os.path.exists(p):
            return f"ERROR: {args['path']} does not exist"
        with open(p, "r", encoding="utf-8") as f:
            lines = [f"{i+1:3d}: {line}" for i, line in enumerate(f)]
        return "".join(lines)[:6000]

    if name == "compile_and_test":
        has_kt = any(f.endswith(".kt") for f in os.listdir(WORKSPACE))
        if has_kt:
            cmd = "kotlinc *.kt -include-runtime -d test_app.jar && java -ea -jar test_app.jar"
        else:
            cmd = "gcc -O2 -g -Wall -pthread *.c -o test_app && ./test_app"
        res = subprocess.run(
            ["bash", "-c", cmd], cwd=WORKSPACE, capture_output=True, text=True, timeout=30
        )
        return f"EXIT_CODE: {res.returncode}\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"[:6000]

    if name == "git_diff":
        res = subprocess.run(
            ["bash", "-c", "git status -s && git diff"],
            cwd=WORKSPACE,
            capture_output=True,
            text=True,
        )
        return (res.stdout or "(no diff)")[:6000]

    raise ValueError(f"Unknown tool: {name}")


def main():
    """Standard MCP JSON-RPC 2.0 event loop over stdin/stdout."""
    for raw_line in sys.stdin:
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        req = json.loads(raw_line)
        req_id = req.get("id")
        method = req.get("method")

        try:
            if method == "initialize":
                result = {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {"name": "unix-sandbox-mcp", "version": "0.1.0"},
                    "capabilities": {"tools": {}},
                }
            elif method == "tools/list":
                result = {"tools": TOOLS}
            elif method == "tools/call":
                params = req.get("params", {})
                text = call_tool(params["name"], params.get("arguments", {}))
                result = {"content": [{"type": "text", "text": text}]}
            else:
                if req_id is None:
                    continue  # Ignore JSON-RPC notifications
                raise ValueError(f"Unsupported method: {method}")

            resp = {"jsonrpc": "2.0", "id": req_id, "result": result}
        except Exception as exc:
            resp = {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": str(exc)}}

        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
