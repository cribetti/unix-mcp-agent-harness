"""Tamper-evident, SHA-256 hash-chained compliance audit logger (audit.jsonl).

Records structured JSONL events for every autonomous engineering session:
  - session_start
  - tool_call
  - security_block
  - compile_and_test
  - git_diff
  - session_end

Each entry links to the previous entry via `prev_hash` -> `entry_hash` (SHA-256 over
canonical JSON), enabling enterprise security/compliance teams to detect any deletion,
insertion, reordering, or post-hoc modification.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import sys
import threading
from typing import Any, Iterable
import uuid

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback
    fcntl = None


GENESIS_HASH = "0" * 64
REQUIRED_FIELDS = ("seq", "timestamp", "session_id", "event_type", "payload", "prev_hash", "entry_hash")
SENSITIVE_KEY_MARKERS = ("api_key", "apikey", "authorization", "secret", "password", "passwd", "token", "private_key")
_NON_SECRET_PLACEHOLDERS = {"", "ollama", "EMPTY", "[REDACTED]", "***REDACTED***"}
_SECRET_TEXT_PATTERNS = (
    re.compile(r"(Bearer\s+)[A-Za-z0-9._\-+/=]{6,}", re.IGNORECASE),
    re.compile(r"\bsk-[A-Za-z0-9_\-]{8,}"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{12,}"),
)
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


def sha256_text(text: str) -> str:
    """Compute hex-encoded SHA-256 digest of a UTF-8 string."""
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _scrub_string(text: str, extra_secrets: Iterable[str] = ()) -> str:
    cleaned = text
    for secret in extra_secrets:
        if secret and secret not in _NON_SECRET_PLACEHOLDERS and len(secret) >= 4:
            cleaned = cleaned.replace(secret, "[REDACTED]")
    cleaned = _SECRET_TEXT_PATTERNS[0].sub(r"\1[REDACTED]", cleaned)
    cleaned = _SECRET_TEXT_PATTERNS[1].sub("[REDACTED]", cleaned)
    cleaned = _SECRET_TEXT_PATTERNS[2].sub("[REDACTED]", cleaned)
    if len(cleaned) > 2000:
        cleaned = cleaned[:2000] + "... [truncated]"
    return cleaned


def redact_sensitive(value: Any, *, key_name: str = "", extra_secrets: Iterable[str] = ()) -> Any:
    """Recursively redact sensitive credential fields and secret tokens before writing to compliance logs."""
    low_key = key_name.lower()
    if low_key and any(marker in low_key for marker in SENSITIVE_KEY_MARKERS):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): redact_sensitive(v, key_name=str(k), extra_secrets=extra_secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_sensitive(item, extra_secrets=extra_secrets) for item in value]
    if isinstance(value, str):
        return _scrub_string(value, extra_secrets=extra_secrets)
    return value


def compute_entry_hash(entry: dict[str, Any]) -> str:
    """Compute canonical SHA-256 hash of an audit entry (excluding `entry_hash`)."""
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _parse_exit_code(output: str) -> int | None:
    for line in (output or "").splitlines():
        if line.startswith("EXIT_CODE:"):
            raw = line.split(":", 1)[1].strip()
            try:
                return int(raw)
            except ValueError:
                return None
    return None


class AuditLogger:
    """Append-only, process-safe, hash-chained JSONL compliance audit logger."""

    def __init__(self, log_path: str, *, session_id: str | None = None, secrets: Iterable[str] = ()):
        self.log_path = os.path.abspath(log_path)
        self.session_id = session_id or uuid.uuid4().hex
        self._lock = threading.Lock()
        self._secrets: list[str] = []
        self.register_secrets(secrets)
        self._seq, self._prev_hash = self._read_chain_tail()

    def register_secrets(self, secrets: Iterable[str]) -> None:
        for secret in secrets:
            if secret and secret not in _NON_SECRET_PLACEHOLDERS and secret not in self._secrets:
                self._secrets.append(secret)

    def _read_chain_tail(self) -> tuple[int, str]:
        if not os.path.isfile(self.log_path):
            return 0, GENESIS_HASH
        last_line = ""
        with open(self.log_path, "r", encoding="utf-8") as f:
            for raw in f:
                stripped = raw.strip()
                if stripped:
                    last_line = stripped
        if not last_line:
            return 0, GENESIS_HASH
        try:
            last_entry = json.loads(last_line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Cannot append to corrupted audit log '{self.log_path}': {exc}") from exc
        if not isinstance(last_entry, dict) or "entry_hash" not in last_entry or "seq" not in last_entry:
            raise ValueError(f"Cannot resume hash chain from malformed last entry in '{self.log_path}'.")
        return int(last_entry["seq"]), str(last_entry["entry_hash"])

    def log_event(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Append a single hash-chained JSONL event and return the written record."""
        with self._lock:
            parent = os.path.dirname(self.log_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(self.log_path, "a+", encoding="utf-8") as f:
                if fcntl is not None:
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    f.seek(0)
                    last_line = ""
                    for raw in f:
                        stripped = raw.strip()
                        if stripped:
                            last_line = stripped
                    if last_line:
                        last_entry = json.loads(last_line)
                        self._seq = int(last_entry["seq"])
                        self._prev_hash = str(last_entry["entry_hash"])
                    else:
                        self._seq = 0
                        self._prev_hash = GENESIS_HASH

                    self._seq += 1
                    entry: dict[str, Any] = {
                        "seq": self._seq,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "session_id": self.session_id,
                        "event_type": event_type,
                        "payload": redact_sensitive(payload, extra_secrets=self._secrets),
                        "prev_hash": self._prev_hash,
                    }
                    entry["entry_hash"] = compute_entry_hash(entry)
                    line = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
                    f.seek(0, os.SEEK_END)
                    f.write(line)
                    f.flush()
                    os.fsync(f.fileno())
                    self._prev_hash = entry["entry_hash"]
                    return entry
                finally:
                    if fcntl is not None:
                        fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    def log_session_start(
        self,
        *,
        workspace: str,
        provider: str,
        model: str,
        base_url: str,
        sandbox: str,
        spec: str,
    ) -> dict[str, Any]:
        return self.log_event(
            "session_start",
            {
                "workspace": workspace,
                "provider": provider,
                "model": model,
                "base_url": base_url,
                "sandbox": sandbox,
                "spec_sha256": sha256_text(spec),
                "spec_preview": spec[:300],
            },
        )

    def log_tool_call(
        self,
        *,
        tool: str,
        arguments: dict[str, Any],
        output: str = "",
        blocked: bool = False,
        turn: int | None = None,
        elapsed_ms: float | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "tool": tool,
            "arguments": arguments,
            "blocked": bool(blocked),
            "output_sha256": sha256_text(output),
            "output_preview": (output or "")[:400],
        }
        if turn is not None:
            payload["turn"] = turn
        if elapsed_ms is not None:
            payload["elapsed_ms"] = round(elapsed_ms, 2)
        return self.log_event("tool_call", payload)

    def log_security_block(
        self,
        *,
        tool: str,
        reason: str,
        target: str = "",
        category: str = "security_violation",
        turn: int | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "tool": tool,
            "target": str(target),
            "category": category,
            "reason": reason,
        }
        if turn is not None:
            payload["turn"] = turn
        return self.log_event("security_block", payload)

    def log_compile_and_test(
        self,
        *,
        output: str,
        exit_code: int | None = None,
        critic_approved: bool | None = None,
        critic_verdict: str | None = None,
        turn: int | None = None,
    ) -> dict[str, Any]:
        resolved_code = exit_code if exit_code is not None else _parse_exit_code(output)
        payload: dict[str, Any] = {
            "exit_code": resolved_code,
            "passed": resolved_code == 0,
            "output_sha256": sha256_text(output),
            "output_preview": (output or "")[:500],
        }
        if critic_approved is not None:
            payload["critic_approved"] = bool(critic_approved)
        if critic_verdict is not None:
            payload["critic_verdict"] = critic_verdict[:500]
        if turn is not None:
            payload["turn"] = turn
        return self.log_event("compile_and_test", payload)

    def log_git_diff(
        self,
        *,
        diff_text: str,
        changed_files: list[str] | None = None,
        status: str = "captured",
    ) -> dict[str, Any]:
        return self.log_event(
            "git_diff",
            {
                "status": status,
                "git_diff_sha256": sha256_text(diff_text),
                "diff_bytes": len((diff_text or "").encode("utf-8")),
                "changed_files": sorted(changed_files) if changed_files is not None else [],
            },
        )

    def log_session_end(
        self,
        *,
        status: str,
        turns: int,
        security_blocks: int = 0,
        critic_rejections: int = 0,
        git_diff: str = "",
    ) -> dict[str, Any]:
        return self.log_event(
            "session_end",
            {
                "status": status,
                "turns": turns,
                "security_blocks": security_blocks,
                "critic_rejections": critic_rejections,
                "git_diff_sha256": sha256_text(git_diff),
            },
        )


def verify_audit_log(log_path: str) -> tuple[bool, list[str], int]:
    """Verify hash-chain integrity, sequence continuity, and entry digests of an audit.jsonl file.

    Returns (is_valid, errors, entry_count).
    """
    errors: list[str] = []
    if not os.path.isfile(log_path):
        return False, [f"Audit log file not found: {log_path}"], 0

    expected_prev = GENESIS_HASH
    count = 0

    with open(log_path, "r", encoding="utf-8") as f:
        for line_no, raw in enumerate(f, 1):
            stripped = raw.strip()
            if not stripped:
                continue
            count += 1
            try:
                entry = json.loads(stripped)
            except json.JSONDecodeError as exc:
                errors.append(f"Line {line_no}: invalid JSON ({exc})")
                continue

            if not isinstance(entry, dict):
                errors.append(f"Line {line_no}: expected JSON object")
                continue

            missing = [k for k in REQUIRED_FIELDS if k not in entry]
            if missing:
                errors.append(f"Line {line_no}: missing required fields {missing}")
                continue

            seq_val = entry["seq"]
            if not isinstance(seq_val, int) or isinstance(seq_val, bool) or seq_val != count:
                errors.append(f"Line {line_no}: sequence mismatch (expected {count}, got {seq_val!r})")

            if not isinstance(entry["session_id"], str) or not entry["session_id"]:
                errors.append(f"Line {line_no}: invalid session_id")

            if not isinstance(entry["event_type"], str) or not entry["event_type"]:
                errors.append(f"Line {line_no}: invalid event_type")

            if entry["prev_hash"] != expected_prev:
                errors.append(
                    f"Line {line_no}: prev_hash chain break (expected {expected_prev[:12]}..., "
                    f"got {str(entry['prev_hash'])[:12]}...)"
                )

            entry_hash = str(entry["entry_hash"])
            recomputed = compute_entry_hash(entry)
            if not _SHA256_HEX_RE.match(entry_hash) or entry_hash != recomputed:
                errors.append(
                    f"Line {line_no}: entry_hash tampering detected (stored {entry_hash[:12]}..., "
                    f"recomputed {recomputed[:12]}...)"
                )

            expected_prev = entry_hash

    if count == 0:
        errors.append("Audit log is empty (0 entries).")

    return len(errors) == 0, errors, count


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify tamper-evident SHA-256 hash chain in audit.jsonl")
    parser.add_argument("--verify", required=True, help="Path to audit.jsonl file to verify")
    args = parser.parse_args()

    ok, errors, count = verify_audit_log(args.verify)
    if ok:
        print(f"OK: Verified {count} hash-chained audit entries in {args.verify}")
        return 0
    print(f"FAILED: Audit log integrity check failed for {args.verify} ({len(errors)} error(s)):", file=sys.stderr)
    for err in errors:
        print(f"  - {err}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
