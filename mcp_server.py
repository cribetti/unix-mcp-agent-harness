import argparse
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys


def resolve_config() -> tuple[str, str]:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--workspace", default=os.environ.get("MCP_WORKSPACE", "./workspace"))
    parser.add_argument("--sandbox", choices=["host", "docker"], default=os.environ.get("MCP_SANDBOX", "host"))
    args, _ = parser.parse_known_args()
    ws = os.path.realpath(os.path.abspath(args.workspace))
    os.makedirs(ws, exist_ok=True)
    return ws, args.sandbox


WORKSPACE, SANDBOX_MODE = resolve_config()

PRUNE_DIRS = {
    ".git",
    ".gradle",
    "build",
    ".idea",
    ".cxx",
    "captures",
    "__pycache__",
    "node_modules",
}

TEXT_EXTENSIONS = {
    ".kt", ".kts", ".java", ".c", ".cpp", ".cc", ".h", ".hpp",
    ".xml", ".gradle", ".properties", ".json", ".toml", ".md", ".txt", ".sh",
}


def safe_path(rel_path: str) -> str:
    """Enforce strict path-jail security (including leaf symlink resolution) inside WORKSPACE."""
    if not rel_path or rel_path == ".":
        return WORKSPACE
    candidate = os.path.abspath(os.path.join(WORKSPACE, rel_path))
    target = os.path.realpath(candidate)
    if os.path.commonpath([WORKSPACE, target]) != WORKSPACE:
        raise ValueError(f"Access denied: '{rel_path}' escapes workspace")
    return target


def sanitize_kotlin(content: str) -> str:
    lines = [l for l in content.splitlines() if not l.strip().startswith("import kotlin.test.")]
    return "\n".join(lines) + ("\n" if content.endswith("\n") or lines else "")


TOOLS = [
    {
        "name": "find_files",
        "description": "List project files matching an optional glob pattern (e.g., '*ViewModel*.kt' or '*.xml'), excluding build/gradle caches.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Filename or path glob pattern (default '*')"},
                "max_results": {"type": "integer", "description": "Max files to return (default 100)"},
            },
        },
    },
    {
        "name": "grep_search",
        "description": "Search for a regex or text pattern across source files. Returns 'path:line:content'.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Regex or substring to search for"},
                "path": {"type": "string", "description": "Relative subdirectory or file to search (default '.')"},
                "max_results": {"type": "integer", "description": "Max matching lines to return (default 60)"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "read_file",
        "description": "Read a file from workspace with line numbers. Optional start_line and end_line for large files.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "start_line": {"type": "integer", "description": "1-based start line (optional)"},
                "end_line": {"type": "integer", "description": "1-based inclusive end line (optional)"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "edit_file",
        "description": "Surgically replace an exact, unique substring in an existing file. Always read_file first to get exact context.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "old_str": {"type": "string", "description": "Exact existing text block to replace (must appear once)"},
                "new_str": {"type": "string", "description": "Replacement text block"},
            },
            "required": ["path", "old_str", "new_str"],
        },
    },
    {
        "name": "write_file",
        "description": "Create a new file or overwrite an entire file inside workspace.",
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
        "name": "compile_and_test",
        "description": "Build and run unit tests (auto-detects Gradle './gradlew testDebugUnitTest', standalone Kotlin, or C).",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "git_diff",
        "description": "Return unified git diff of source changes in workspace.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def _iter_workspace_files(root_dir: str):
    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = sorted(d for d in dirnames if d not in PRUNE_DIRS)
        for fname in sorted(filenames):
            full = os.path.join(dirpath, fname)
            rel = os.path.relpath(full, WORKSPACE)
            yield rel, full


def tool_find_files(args: dict) -> str:
    pattern = args.get("pattern") or "*"
    max_results = int(args.get("max_results") or 100)
    matches = list()
    for rel, _ in _iter_workspace_files(WORKSPACE):
        fname = os.path.basename(rel)
        if fnmatch.fnmatch(fname, pattern) or fnmatch.fnmatch(rel, pattern):
            matches.append(rel)
            if len(matches) >= max_results:
                break
    if not matches:
        return f"No files matched pattern '{pattern}'."
    suffix = f"\n... (truncated at {max_results} results)" if len(matches) == max_results else ""
    return "\n".join(matches) + suffix


def tool_grep_search(args: dict) -> str:
    query = args["query"]
    rel_sub = args.get("path") or "."
    max_results = int(args.get("max_results") or 60)
    search_root = safe_path(rel_sub)

    if not os.path.exists(search_root):
        return f"ERROR: Path '{rel_sub}' does not exist."

    if shutil.which("rg"):
        cmd = ["rg", "-n", "--no-heading", "--color", "never", "-m", str(max_results)]
        for pdir in PRUNE_DIRS:
            cmd.extend(["-g", f"!{pdir}/**", "-g", f"!{pdir}"])
        cmd.extend([query, search_root])
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if res.returncode not in (0, 1):
            return f"ERROR: rg failed: {res.stderr.strip()}"
        out_lines = list()
        for line in res.stdout.splitlines():
            if line.startswith(WORKSPACE + os.sep):
                line = line[len(WORKSPACE) + 1 :]
            elif line == WORKSPACE:
                line = "."
            if len(line) > 240:
                line = line[:240] + "..."
            out_lines.append(line)
            if len(out_lines) >= max_results:
                break
        return "\n".join(out_lines) if out_lines else f"No matches for '{query}'."

    try:
        rx = re.compile(query)
    except re.error as exc:
        return f"ERROR: Invalid regex '{query}': {exc}"

    targets = (
        [(os.path.relpath(search_root, WORKSPACE), search_root)]
        if os.path.isfile(search_root)
        else list(_iter_workspace_files(search_root))
    )
    results = list()
    for rel, full in targets:
        _, ext = os.path.splitext(full)
        if ext.lower() not in TEXT_EXTENSIONS and os.path.basename(full) != "gradlew":
            continue
        try:
            with open(full, "r", encoding="utf-8", errors="ignore") as f:
                for idx, line in enumerate(f, 1):
                    if rx.search(line):
                        snippet = line.rstrip("\r\n")
                        if len(snippet) > 240:
                            snippet = snippet[:240] + "..."
                        results.append(f"{rel}:{idx}:{snippet}")
                        if len(results) >= max_results:
                            return "\n".join(results)
        except OSError:
            continue
    return "\n".join(results) if results else f"No matches for '{query}'."


def tool_read_file(args: dict) -> str:
    p = safe_path(args["path"])
    if not os.path.exists(p):
        return f"ERROR: {args['path']} does not exist"
    if os.path.isdir(p):
        return f"ERROR: {args['path']} is a directory; use find_files instead"

    with open(p, "r", encoding="utf-8", errors="replace") as f:
        all_lines = f.readlines()

    total = len(all_lines)
    start = max(1, int(args.get("start_line") or 1))
    end = min(total, int(args.get("end_line") or total))
    if start > end and total > 0:
        return f"ERROR: Invalid range {start}..{end} for file with {total} lines"

    numbered = [f"{i:4d}: {all_lines[i - 1]}" for i in range(start, end + 1)]
    text = "".join(numbered)
    if len(text) > 7000:
        text = text[:7000] + f"\n... [truncated; file has {total} lines—use start_line/end_line to read further]"
    return text or "(empty file)"

def tool_edit_file(args: dict) -> str:
    p = safe_path(args["path"])
    if not os.path.exists(p):
        return f"ERROR: {args['path']} does not exist. Use write_file to create new files."

    old_str = args["old_str"]
    new_str = args["new_str"]
    if not old_str:
        return "ERROR: old_str cannot be empty."

    with open(p, "r", encoding="utf-8") as f:
        content = f.read()

    occurrences = content.count(old_str)
    if occurrences == 0:
        return (
            f"ERROR: old_str was not found verbatim in {args['path']}. "
            "Call read_file first and copy exact indentation and lines."
        )
    if occurrences > 1:
        lines = content.splitlines()
        first_old_line = old_str.splitlines()[0]
        hits = [str(i + 1) for i, l in enumerate(lines) if first_old_line in l]
        return (
            f"ERROR: old_str matched {occurrences} times in {args['path']} (around lines {', '.join(hits)}). "
            "Include 2-3 surrounding lines in old_str so the match is unique."
        )

    updated = content.replace(old_str, new_str, 1)
    if p.endswith(".kt"):
        updated = sanitize_kotlin(updated)

    with open(p, "w", encoding="utf-8") as f:
        f.write(updated)

    updated_lines = updated.splitlines()
    edit_start_line = content[: content.index(old_str)].count("\n") + 1
    ctx_start = max(1, edit_start_line - 2)
    ctx_end = min(len(updated_lines), edit_start_line + len(new_str.splitlines()) + 2)
    preview = "\n".join(f"{i:4d}: {updated_lines[i - 1]}" for i in range(ctx_start, ctx_end + 1))
    return f"Edited {args['path']} successfully:\n{preview}"


def tool_write_file(args: dict) -> str:
    p = safe_path(args["path"])
    os.makedirs(os.path.dirname(p), exist_ok=True)
    content = args["content"]
    if p.endswith(".kt"):
        content = sanitize_kotlin(content)
    with open(p, "w", encoding="utf-8") as f:
        f.write(content)
    return f"Wrote {len(content)} bytes to {args['path']}"


def build_test_command(
    workspace: str,
    sandbox: str = "host",
    docker_image: str | None = None,
) -> tuple[list[str], int]:
    """Build the compile_and_test command and timeout for host or --network=none docker execution."""
    gradlew = os.path.join(workspace, "gradlew")
    if os.path.exists(gradlew):
        cmd = "chmod +x ./gradlew && ./gradlew testDebugUnitTest --stacktrace"
        timeout_sec = 180
        default_img = "eclipse-temurin:21"
    elif any(f.endswith(".kt") for f in os.listdir(workspace)):
        cmd = (
            'KLIB=$(dirname "$(realpath "$(which kotlinc)")")/../libexec/lib; '
            'CP=$(ls "$KLIB"/kotlin-test*.jar 2>/dev/null | tr "\\n" ":"); '
            'kotlinc -cp "$CP" *.kt -include-runtime -d test_app.jar && '
            'java -ea -cp "test_app.jar:$CP" MainKt'
        )
        timeout_sec = 45
        default_img = "eclipse-temurin:21"
    else:
        cmd = "gcc -O2 -g -Wall -pthread *.c -o test_app && ./test_app"
        timeout_sec = 30
        default_img = "gcc:14"

    if sandbox == "docker":
        img = docker_image or os.environ.get("MCP_DOCKER_IMAGE", default_img)
        return (
            [
                "docker",
                "run",
                "--rm",
                "--network=none",
                "-v",
                f"{workspace}:/workspace",
                "-w",
                "/workspace",
                img,
                "bash",
                "-c",
                cmd,
            ],
            timeout_sec,
        )
    return ["bash", "-c", cmd], timeout_sec


def tool_compile_and_test() -> str:
    if SANDBOX_MODE == "docker" and not shutil.which("docker"):
        return "EXIT_CODE: 1\nSTDOUT:\n\nSTDERR:\nERROR: --sandbox docker requested, but 'docker' CLI was not found on PATH."

    full_cmd, timeout_sec = build_test_command(WORKSPACE, sandbox=SANDBOX_MODE)
    try:
        res = subprocess.run(
            full_cmd,
            cwd=WORKSPACE,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
    except subprocess.TimeoutExpired:
        return f"EXIT_CODE: 124\nSTDOUT:\n\nSTDERR:\nBuild/test timed out after {timeout_sec}s."

    combined = f"EXIT_CODE: {res.returncode}\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"
    if len(combined) > 7500:
        combined = combined[:2000] + "\n... [middle truncated] ...\n" + combined[-5500:]
    return combined


def tool_git_diff() -> str:
    source_exts = {
        ".kt", ".kts", ".java", ".c", ".cpp", ".h", ".hpp", ".xml", ".gradle", ".properties", ".md",
    }
    untracked_or_src = [
        rel for rel, _ in _iter_workspace_files(WORKSPACE)
        if os.path.splitext(rel)[1].lower() in source_exts
    ]
    if untracked_or_src:
        subprocess.run(
            ["git", "add", "-N", "--"] + untracked_or_src,
            cwd=WORKSPACE,
            capture_output=True,
        )
    res = subprocess.run(
        ["git", "diff", "HEAD", "--", ".", ":(exclude)build", ":(exclude).gradle"],
        cwd=WORKSPACE,
        capture_output=True,
        text=True,
    )
    diff = res.stdout
    if len(diff) > 10000:
        diff = diff[:10000] + "\n... [diff truncated at 10,000 chars]"
    return diff or "No changes."


def call_tool(name: str, args: dict) -> str:
    if name == "find_files":
        return tool_find_files(args)
    if name == "grep_search":
        return tool_grep_search(args)
    if name == "read_file":
        return tool_read_file(args)
    if name == "edit_file":
        return tool_edit_file(args)
    if name == "write_file":
        return tool_write_file(args)
    if name == "compile_and_test":
        return tool_compile_and_test()
    if name == "git_diff":
        return tool_git_diff()
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
                    "serverInfo": {"name": "unix-sandbox-mcp", "version": "0.2.0"},
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
                    continue
                raise ValueError(f"Unsupported method: {method}")

            resp = {"jsonrpc": "2.0", "id": req_id, "result": result}
        except Exception as exc:
            resp = {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": str(exc)}}

        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
