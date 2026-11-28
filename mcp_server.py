import argparse
from datetime import datetime, timezone
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
from urllib.parse import unquote


def resolve_config() -> tuple[str, str, str]:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--workspace", default=os.environ.get("MCP_WORKSPACE", "./workspace"))
    parser.add_argument("--sandbox", choices=["host", "docker"], default=os.environ.get("MCP_SANDBOX", "host"))
    parser.add_argument("--security-log", default=os.environ.get("MCP_SECURITY_LOG", ""))
    args, _ = parser.parse_known_args()
    ws = os.path.realpath(os.path.abspath(args.workspace))
    os.makedirs(ws, exist_ok=True)
    security_log_path = os.path.abspath(args.security_log) if args.security_log else ""
    return ws, args.sandbox, security_log_path


WORKSPACE, SANDBOX_MODE, SECURITY_LOG_PATH = resolve_config()

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

SENSITIVE_DIRS = {".git", ".ssh", ".aws", ".gnupg"}

SENSITIVE_EXACT_NAMES = {
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".dockercfg",
    "id_rsa",
    "id_rsa.pub",
    "id_ed25519",
    "id_ed25519.pub",
    "id_ecdsa",
    "id_dsa",
    "authorized_keys",
    "known_hosts",
    "credentials",
    "credentials.json",
    "credentials.yml",
    "credentials.yaml",
    "credentials.ini",
    "credentials.xml",
    "aws_credentials",
    "secrets.json",
    "secrets.yaml",
    "secrets.yml",
    "secrets.properties",
    "secrets.toml",
    "secrets.env",
    "keystore.properties",
    "service-account.json",
    "service_account.json",
    "token.json",
    "auth.json",
    "master.key",
}

SENSITIVE_EXTENSIONS = {
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".jks",
    ".keystore",
    ".kdbx",
    ".secret",
    ".secrets",
}

SENSITIVE_NAME_PATTERNS = (
    "*credentials*.json",
    "*credentials*.yaml",
    "*credentials*.yml",
    "*service*account*.json",
)

DANGEROUS_COMMAND_PATTERNS = (
    (r"\brm\s+-[a-zA-Z]*[rf][a-zA-Z]*\b", "destructive rm"),
    (r"\bgit\s+push\s+(?:--force|-f)\b", "destructive git push --force"),
    (r"\b(?:curl|wget|nc|ncat|netcat|socat|telnet|scp|sftp|rsync)\b", "unauthorized network binary"),
    (r"/dev/(?:tcp|udp)/", "network device redirection"),
    (r"\|\s*(?:ba)?sh\b", "piped shell execution"),
    (r"\b(?:ba)?sh\s+-c\b", "nested shell command"),
    (r"\b(?:python[23]?\s+-c|perl\s+-e|mkfifo|base64\s+(?:-d|--decode))\b", "unauthorized shell/payload command"),
    (r":\(\)\s*\{", "fork bomb"),
)

SOCKET_EGRESS_PATTERNS = (
    (r"\bsocket\s*\(\s*AF_INET6?\b", "raw IPv4/IPv6 socket"),
    (r"\bjava\.net\.(?:Socket|ServerSocket|HttpURLConnection|URL)\b", "Java network socket/URL"),
    (r"\bHttpURLConnection\b", "HTTP network connection"),
)

TEXT_EXTENSIONS = {
    ".kt", ".kts", ".java", ".c", ".cpp", ".cc", ".h", ".hpp",
    ".xml", ".gradle", ".properties", ".json", ".toml", ".md", ".txt", ".sh",
}


class SecurityViolationError(ValueError):
    """Structured security violation raised when an MCP tool call breaches sandbox policy."""

    def __init__(self, message: str, *, tool: str = "", target: str = "", category: str = "security_violation"):
        super().__init__(message)
        self.tool = tool
        self.target = target
        self.reason = message
        self.category = category


def log_security_violation(tool: str, target: str, reason: str, category: str = "security_violation") -> dict:
    """Emit a structured JSON security violation event to stderr and optional SECURITY_LOG_PATH."""
    event = {
        "event_type": "security_violation",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": tool,
        "target": str(target),
        "reason": reason,
        "category": category,
        "workspace": WORKSPACE,
        "sandbox": SANDBOX_MODE,
    }
    line = json.dumps(event, ensure_ascii=False) + "\n"
    if SECURITY_LOG_PATH:
        parent = os.path.dirname(SECURITY_LOG_PATH)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(SECURITY_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()
    sys.stderr.write(line)
    sys.stderr.flush()
    return event


def _deny(tool: str, target: str, reason: str, category: str) -> None:
    log_security_violation(tool, target, reason, category=category)
    raise SecurityViolationError(reason, tool=tool, target=target, category=category)


def is_sensitive_path(rel_path: str) -> tuple[bool, str]:
    """Check whether a workspace-relative path targets blocked secret/credential directories or files."""
    if not rel_path or rel_path == ".":
        return False, ""
    norm = rel_path.replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    norm = norm.lstrip("/")
    if not norm:
        return False, ""
    parts = [p.lower() for p in norm.split("/") if p and p != "."]
    if not parts:
        return False, ""
    for part in parts:
        if part in SENSITIVE_DIRS:
            return True, f"blocked directory '{part}'"
    base = parts[-1]
    if base == ".env" or base.startswith(".env."):
        return True, "environment secret file"
    if base in SENSITIVE_EXACT_NAMES:
        return True, f"credential/secret file '{base}'"
    _, ext = os.path.splitext(base)
    if ext in SENSITIVE_EXTENSIONS:
        return True, f"private key/keystore extension '{ext}'"
    for pat in SENSITIVE_NAME_PATTERNS:
        if fnmatch.fnmatch(base, pat):
            return True, f"credential file matching '{pat}'"
    return False, ""


def safe_path(rel_path: str, *, tool: str = "safe_path") -> str:
    """Enforce strict path-jail security (including traversal, URL encoding, symlinks, and secrets) inside WORKSPACE."""
    if not rel_path or rel_path == ".":
        return WORKSPACE
    if "\x00" in rel_path or "%00" in rel_path.lower():
        _deny(tool, rel_path, f"Access denied: '{rel_path}' contains null byte and escapes workspace", "path_traversal")

    decoded = rel_path
    for _ in range(3):
        nxt = unquote(decoded)
        if nxt == decoded:
            break
        decoded = nxt
    if "\x00" in decoded:
        _deny(
            tool,
            rel_path,
            f"Access denied: '{rel_path}' contains URL-encoded null byte and escapes workspace",
            "path_traversal",
        )
    if decoded != rel_path:
        decoded_norm = decoded.replace("\\", "/")
        if decoded_norm.startswith(("/", "~")) or ".." in decoded_norm.split("/"):
            _deny(
                tool,
                rel_path,
                f"Access denied: URL-encoded path '{rel_path}' escapes workspace",
                "path_traversal",
            )
        dec_target = os.path.realpath(os.path.abspath(os.path.join(WORKSPACE, os.path.expanduser(decoded_norm))))
        if os.path.commonpath([WORKSPACE, dec_target]) != WORKSPACE:
            _deny(
                tool,
                rel_path,
                f"Access denied: URL-encoded path '{rel_path}' escapes workspace",
                "path_traversal",
            )
        dec_rel = os.path.relpath(dec_target, WORKSPACE)
        is_sens, detail = is_sensitive_path(dec_rel)
        if is_sens:
            _deny(
                tool,
                rel_path,
                f"Access denied: URL-encoded path '{rel_path}' blocked by sensitive file policy ({detail})",
                "sensitive_file",
            )

    if rel_path.startswith("~"):
        _deny(tool, rel_path, f"Access denied: '{rel_path}' home-relative path escapes workspace", "path_traversal")

    candidate = os.path.abspath(os.path.join(WORKSPACE, rel_path))
    target = os.path.realpath(candidate)
    if os.path.commonpath([WORKSPACE, target]) != WORKSPACE:
        if os.path.commonpath([WORKSPACE, candidate]) == WORKSPACE:
            _deny(tool, rel_path, f"Access denied: '{rel_path}' symlink escapes workspace", "symlink_escape")
        _deny(tool, rel_path, f"Access denied: '{rel_path}' escapes workspace", "path_traversal")

    for check_path in (os.path.relpath(target, WORKSPACE), os.path.relpath(candidate, WORKSPACE)):
        is_sens, detail = is_sensitive_path(check_path)
        if is_sens:
            _deny(
                tool,
                rel_path,
                f"Access denied: '{rel_path}' is blocked by sensitive file policy ({detail})",
                "sensitive_file",
            )
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
                "path": {"type": "string", "description": "Relative subdirectory to search (default '.')"},
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
    skip_dirs = PRUNE_DIRS | SENSITIVE_DIRS
    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = sorted(d for d in dirnames if d not in skip_dirs)
        for fname in sorted(filenames):
            full = os.path.join(dirpath, fname)
            real = os.path.realpath(full)
            if os.path.commonpath([WORKSPACE, real]) != WORKSPACE:
                continue
            rel = os.path.relpath(full, WORKSPACE)
            real_rel = os.path.relpath(real, WORKSPACE)
            if is_sensitive_path(rel)[0] or is_sensitive_path(real_rel)[0]:
                continue
            yield rel, full


def tool_find_files(args: dict) -> str:
    pattern = (args.get("pattern") or "*").strip()
    rel_sub = args.get("path") or "."
    search_root = safe_path(rel_sub, tool="find_files")
    if not os.path.exists(search_root):
        return f"ERROR: Path '{rel_sub}' does not exist."
    max_results = int(args.get("max_results") or 100)
    patterns = [p for p in re.split(r"[\s,]+", pattern) if p] or ["*"]
    for pat in patterns:
        probe = re.sub(r"[*?\[\]]", "x", pat)
        safe_path(probe, tool="find_files")
        stripped = pat.strip().rstrip("*?/")
        if stripped:
            is_sens, detail = is_sensitive_path(stripped)
            if is_sens:
                _deny(
                    "find_files",
                    pat,
                    f"Access denied: pattern '{pat}' targets sensitive files ({detail})",
                    "sensitive_file",
                )

    all_rels = [rel for rel, _ in _iter_workspace_files(search_root)]
    matches = []
    for rel in all_rels:
        fname = os.path.basename(rel)
        if any(fnmatch.fnmatch(fname, pat) or fnmatch.fnmatch(rel, pat) for pat in patterns):
            matches.append(rel)
            if len(matches) >= max_results:
                break
    if not matches:
        if all_rels:
            preview = "\n".join(all_rels[:25])
            return f"No files matched pattern '{pattern}'. Workspace files:\n{preview}"
        return f"No files matched pattern '{pattern}'."
    suffix = f"\n... (truncated at {max_results} results)" if len(matches) == max_results else ""
    return "\n".join(matches) + suffix


def tool_grep_search(args: dict) -> str:
    query = args["query"]
    rel_sub = args.get("path") or "."
    max_results = int(args.get("max_results") or 60)
    search_root = safe_path(rel_sub, tool="grep_search")

    if not os.path.exists(search_root):
        return f"ERROR: Path '{rel_sub}' does not exist."

    if shutil.which("rg"):
        cmd = ["rg", "-n", "--no-heading", "--color", "never", "-m", str(max_results)]
        for pdir in sorted(PRUNE_DIRS | SENSITIVE_DIRS):
            cmd.extend(["-g", f"!{pdir}/**", "-g", f"!{pdir}"])
        for sglob in (
            ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore",
            "*.kdbx", "credentials.*", "secrets.*", "id_rsa*", "id_ed25519*",
            "service-account.json", "service_account.json", "keystore.properties",
            ".netrc", ".npmrc",
        ):
            cmd.extend(["-g", f"!{sglob}", "-g", f"!**/{sglob}"])
        cmd.extend(["--", query, search_root])
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if res.returncode not in (0, 1):
            return f"ERROR: rg failed: {res.stderr.strip()}"
        out_lines = list()
        for line in res.stdout.splitlines():
            if line.startswith(WORKSPACE + os.sep):
                line = line[len(WORKSPACE) + 1 :]
            elif line == WORKSPACE:
                line = "."
            if ":" in line:
                cand_path = line.split(":", 1)[0]
                if not cand_path.isdigit() and is_sensitive_path(cand_path)[0]:
                    continue
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
    p = safe_path(args["path"], tool="read_file")
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

def _try_unique_indent_edit(content: str, old_str: str, new_str: str) -> tuple[str | None, str | None]:
    """Fallback when exact match fails solely due to uniform leading indentation mismatch."""
    old_lines = old_str.splitlines()
    if not old_lines or not any(l.strip() for l in old_lines):
        return None, None

    content_lines = content.splitlines()
    n = len(old_lines)
    if n > len(content_lines):
        return None, None

    stripped_old = [l.strip() for l in old_lines]
    hit_indices = [
        i for i in range(len(content_lines) - n + 1)
        if [l.strip() for l in content_lines[i : i + n]] == stripped_old
    ]
    if len(hit_indices) > 1:
        hits = ", ".join(str(i + 1) for i in hit_indices)
        return None, f"ERROR: old_str matched {len(hit_indices)} blocks ignoring indentation (lines {hits}). Include more surrounding context."
    if not hit_indices:
        return None, None

    start_idx = hit_indices[0]
    matched_block = content_lines[start_idx : start_idx + n]
    target_indent = next((l[: len(l) - len(l.lstrip(" \t"))] for l in matched_block if l.strip()), "")
    old_indent = next((l[: len(l) - len(l.lstrip(" \t"))] for l in old_lines if l.strip()), "")

    new_lines_raw = new_str.splitlines()
    reindented = []
    for line in new_lines_raw:
        if not line.strip():
            reindented.append("")
        elif old_indent and line.startswith(old_indent):
            reindented.append(target_indent + line[len(old_indent) :])
        elif not old_indent and not line.startswith(target_indent):
            reindented.append(target_indent + line)
        else:
            reindented.append(line)

    merged = content_lines[:start_idx] + reindented + content_lines[start_idx + n :]
    updated = "\n".join(merged) + ("\n" if content.endswith("\n") else "")
    return updated, None


def tool_edit_file(args: dict) -> str:
    p = safe_path(args["path"], tool="edit_file")
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
        updated, indent_err = _try_unique_indent_edit(content, old_str, new_str)
        if indent_err:
            return indent_err
        if updated is None:
            return (
                f"ERROR: old_str was not found verbatim in {args['path']}. "
                "Call read_file first and copy exact indentation and lines, or use write_file to rewrite the file."
            )
        edit_start_line = next(
            (i + 1 for i, (a, b) in enumerate(zip(content.splitlines(), updated.splitlines())) if a != b),
            1,
        )
    elif occurrences > 1:
        lines = content.splitlines()
        first_old_line = old_str.splitlines()[0]
        hits = [str(i + 1) for i, l in enumerate(lines) if first_old_line in l]
        return (
            f"ERROR: old_str matched {occurrences} times in {args['path']} (around lines {', '.join(hits)}). "
            "Include 2-3 surrounding lines in old_str so the match is unique."
        )
    else:
        updated = content.replace(old_str, new_str, 1)
        edit_start_line = content[: content.index(old_str)].count("\n") + 1

    if p.endswith(".kt"):
        updated = sanitize_kotlin(updated)

    with open(p, "w", encoding="utf-8") as f:
        f.write(updated)

    updated_lines = updated.splitlines()
    ctx_start = max(1, edit_start_line - 2)
    ctx_end = min(len(updated_lines), edit_start_line + len(new_str.splitlines()) + 2)
    preview = "\n".join(f"{i:4d}: {updated_lines[i - 1]}" for i in range(ctx_start, ctx_end + 1))
    return f"Edited {args['path']} successfully:\n{preview}"


def tool_write_file(args: dict) -> str:
    p = safe_path(args["path"], tool="write_file")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    content = args["content"]
    if p.endswith(".kt"):
        content = sanitize_kotlin(content)
    with open(p, "w", encoding="utf-8") as f:
        f.write(content)
    return f"Wrote {len(content)} bytes to {args['path']}"


def _find_cmake_bin() -> str:
    """Locate cmake on PATH or in Android SDK cmake prebuilts."""
    found = shutil.which("cmake")
    if found:
        return "cmake"
    sdk_root = os.path.expanduser("~/Library/Android/sdk/cmake")
    if os.path.isdir(sdk_root):
        for ver in sorted(os.listdir(sdk_root), reverse=True):
            cand = os.path.join(sdk_root, ver, "bin", "cmake")
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                return cand
    return "cmake"


def build_test_command(
    workspace: str,
    sandbox: str = "host",
    docker_image: str | None = None,
) -> tuple[list[str], int]:
    """Build the compile_and_test command and timeout for host or --network=none docker execution."""
    gradlew = os.path.join(workspace, "gradlew")
    cmakelists = os.path.join(workspace, "CMakeLists.txt")
    entries = os.listdir(workspace)
    if os.path.exists(gradlew):
        cmd = "chmod +x ./gradlew && ./gradlew testDebugUnitTest --stacktrace"
        timeout_sec = 180
        default_img = "eclipse-temurin:21"
    elif os.path.exists(cmakelists):
        cmake_bin = "cmake" if sandbox == "docker" else _find_cmake_bin()
        ctest_bin = (
            "ctest"
            if sandbox == "docker" or cmake_bin == "cmake"
            else os.path.join(os.path.dirname(cmake_bin), "ctest")
        )
        cmd = (
            f'"{cmake_bin}" -S . -B build && '
            f'"{cmake_bin}" --build build && '
            f'"{ctest_bin}" --test-dir build --output-on-failure'
        )
        timeout_sec = 60
        default_img = "gcc:14"
    elif any(f.endswith(".kt") for f in entries):
        cmd = (
            'KLIB=$(dirname "$(realpath "$(which kotlinc)")")/../libexec/lib; '
            'CP=$(ls "$KLIB"/kotlin-test*.jar 2>/dev/null | tr "\\n" ":"); '
            'kotlinc -cp "$CP" *.kt -include-runtime -d test_app.jar && '
            'java -ea -cp "test_app.jar:$CP" MainKt'
        )
        timeout_sec = 45
        default_img = "eclipse-temurin:21"
    elif any(f.endswith((".cpp", ".cc")) for f in entries):
        cmd = "g++ -std=c++17 -O2 -g -Wall -pthread *.cpp -o test_app && ./test_app"
        timeout_sec = 30
        default_img = "gcc:14"
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


def validate_compile_workspace(workspace: str) -> None:
    """Reject poisoned filenames or malicious shell/network commands before compile_and_test execution."""
    for fname in sorted(os.listdir(workspace)):
        if re.search(r"[;&|`$\n\r<>]", fname):
            _deny(
                "compile_and_test",
                fname,
                f"Access denied: unsafe filename '{fname}' contains shell metacharacters",
                "command_injection",
            )
        _, ext = os.path.splitext(fname)
        if ext.lower() in {".c", ".cpp", ".cc", ".kt", ".kts"} and fname.startswith(("-", "@")):
            _deny(
                "compile_and_test",
                fname,
                f"Access denied: unsafe compiler flag/response filename '{fname}'",
                "command_injection",
            )

    for build_file in ("gradlew", "CMakeLists.txt"):
        fpath = os.path.join(workspace, build_file)
        if not os.path.isfile(fpath):
            continue
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            continue
        for pat, label in DANGEROUS_COMMAND_PATTERNS:
            if re.search(pat, text, re.IGNORECASE):
                _deny(
                    "compile_and_test",
                    build_file,
                    f"Access denied: malicious command pattern ({label}) detected in {build_file}",
                    "command_injection",
                )
        if build_file == "CMakeLists.txt" and re.search(
            r"execute_process\s*\(.*?(?:bash|sh\s+-c|curl|wget|nc\b|ncat|netcat|rm\s+-|/dev/(?:tcp|udp)/|python[23]?\s+-c)",
            text,
            re.IGNORECASE | re.DOTALL,
        ):
            _deny(
                "compile_and_test",
                build_file,
                "Access denied: malicious execute_process command detected in CMakeLists.txt",
                "command_injection",
            )

    exec_markers = ("system(", "popen(", "Runtime.getRuntime().exec", "ProcessBuilder")
    for fname in sorted(os.listdir(workspace)):
        if os.path.splitext(fname)[1].lower() not in {".c", ".cpp", ".cc", ".kt"}:
            continue
        fpath = os.path.join(workspace, fname)
        if not os.path.isfile(fpath):
            continue
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                src = f.read()
        except OSError:
            continue
        for pat, label in SOCKET_EGRESS_PATTERNS:
            if re.search(pat, src):
                _deny(
                    "compile_and_test",
                    fname,
                    f"Access denied: unauthorized network socket pattern ({label}) detected in {fname}",
                    "command_injection",
                )
        if any(marker in src for marker in exec_markers):
            for pat, label in DANGEROUS_COMMAND_PATTERNS:
                if re.search(pat, src, re.IGNORECASE):
                    _deny(
                        "compile_and_test",
                        fname,
                        f"Access denied: malicious command execution ({label}) detected in {fname}",
                        "command_injection",
                    )


def tool_compile_and_test(args: dict | None = None) -> str:
    if args:
        _deny(
            "compile_and_test",
            json.dumps(args, sort_keys=True),
            f"Access denied: compile_and_test does not accept arguments or shell commands ({sorted(args.keys())})",
            "command_injection",
        )
    validate_compile_workspace(WORKSPACE)
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
        if os.path.splitext(rel)[1].lower() in source_exts or os.path.basename(rel) == "CMakeLists.txt"
    ]
    if untracked_or_src:
        subprocess.run(
            ["git", "add", "-N", "--"] + untracked_or_src,
            cwd=WORKSPACE,
            capture_output=True,
        )
    res = subprocess.run(
        ["git", "diff", "HEAD", "--ignore-submodules=all", "--", ".", ":(exclude)build", ":(exclude).gradle"],
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
        return tool_compile_and_test(args)
    if name == "git_diff":
        return tool_git_diff()
    _deny(name, str(args), f"Unknown tool: {name}", "unknown_tool")


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
