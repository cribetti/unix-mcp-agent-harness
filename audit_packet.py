import argparse
import json
import os
import random
import re
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Any


SOURCE_EXTS = {
    ".kt", ".kts", ".java", ".c", ".cpp", ".cc", ".h", ".hpp",
    ".xml", ".gradle", ".properties", ".md",
}


def parse_diff_stats(diff: str) -> tuple[list[str], int, int, bool]:
    """Return (modified_source_files, added_lines, removed_lines, has_submodule_only)."""
    files_with_hunks: list[str] = []
    current_file: str | None = None
    has_hunk = False
    is_subproject = False
    saw_subproject = False
    added = 0
    removed = 0

    for line in diff.splitlines():
        if line.startswith("diff --git "):
            if current_file and has_hunk and not is_subproject:
                files_with_hunks.append(current_file)
            parts = line.split(" ")
            b_part = parts[-1] if len(parts) >= 4 else ""
            current_file = b_part[2:] if b_part.startswith("b/") else b_part
            has_hunk = False
            is_subproject = False
        elif line.startswith("@@ "):
            has_hunk = True
        elif "Subproject commit " in line:
            is_subproject = True
            saw_subproject = True
        elif line.startswith("+") and not line.startswith("+++ "):
            if not is_subproject:
                added += 1
        elif line.startswith("-") and not line.startswith("--- "):
            if not is_subproject:
                removed += 1

    if current_file and has_hunk and not is_subproject:
        files_with_hunks.append(current_file)

    source_files = [
        p for p in files_with_hunks
        if os.path.splitext(p)[1].lower() in SOURCE_EXTS or os.path.basename(p) == "CMakeLists.txt"
    ]
    submodule_only = saw_subproject and not source_files
    return source_files, added, removed, submodule_only


def classify_language(files: list[str], spec: str = "") -> str:
    """Classify trajectory language kind as 'CPP', 'KT', or 'C'."""
    if any(f.endswith((".cpp", ".cc", ".hpp", ".h")) or os.path.basename(f) == "CMakeLists.txt" for f in files):
        if any(f.endswith((".cpp", ".cc", ".hpp")) or os.path.basename(f) == "CMakeLists.txt" for f in files):
            return "CPP"
    if any(f.endswith((".kt", ".kts", ".java")) for f in files):
        return "KT"
    if any(f.endswith((".c", ".h")) for f in files):
        return "C"
    low = spec.lower()
    if "cmakelists" in low or ".cpp" in low:
        return "CPP"
    if ".kt" in low or "kotlin" in low:
        return "KT"
    return "C"


def extract_tool_trace(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extract a compact, faithful tool-call and tool-result trace from trajectory messages."""
    trace: list[dict[str, Any]] = []
    for idx, msg in enumerate(messages):
        role = msg.get("role", "")
        if role == "assistant" and msg.get("tool_calls"):
            for tc in msg["tool_calls"]:
                fn = tc.get("function", {})
                args = fn.get("arguments", {})
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except json.JSONDecodeError:
                        pass
                # Summarize large file contents while preserving path/keys/small patches verbatim
                if isinstance(args, dict):
                    compact_args = {}
                    for k, v in args.items():
                        if isinstance(v, str) and len(v) > 400:
                            compact_args[k] = v[:400] + f"\n... [{len(v)} chars]"
                        else:
                            compact_args[k] = v
                else:
                    compact_args = args
                trace.append({"step": idx, "tool": fn.get("name", ""), "arguments": compact_args})
        elif role == "tool":
            content = msg.get("content") or ""
            preview = content if len(content) <= 350 else content[:350] + f"\n... [{len(content)} chars]"
            trace.append({"step": idx, "tool_result": preview})
    return trace


def analyze_trajectories(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute counts, per-row diff metrics, and deterministic sanity flags."""
    by_model: dict[str, int] = {}
    by_lang: dict[str, int] = {}
    approved_rows: list[dict[str, Any]] = []
    rejected_count = 0
    row_audits: list[dict[str, Any]] = []
    flagged: list[dict[str, Any]] = []

    for idx, rec in enumerate(rows):
        verdict = (rec.get("critic_verdict") or "").strip()
        is_approved = verdict.startswith("APPROVED:")
        if is_approved:
            approved_rows.append(rec)
        else:
            rejected_count += 1

        model = rec.get("model", "unknown")
        by_model[model] = by_model.get(model, 0) + 1

        diff = rec.get("git_diff") or ""
        src_files, added, removed, submodule_only = parse_diff_stats(diff)
        lang = classify_language(src_files, rec.get("spec", ""))
        by_lang[lang] = by_lang.get(lang, 0) + 1

        turns = int(rec.get("turns") or 0)
        rejections = int(rec.get("critic_rejections") or 0)
        flags: list[str] = []

        if not src_files:
            flags.append("zero_source_diff" if not submodule_only else "submodule_only_diff")
        if turns <= 1:
            flags.append("suspicious_1_turn")
        if turns >= 8 or rejections >= 2:
            flags.append(f"noisy_multi_turn(turns={turns},rej={rejections})")

        # Flag repeated consecutive tool errors or identical tool calls in trace
        msgs = rec.get("messages", [])
        last_sig = None
        edit_errors = 0
        for m in msgs:
            if m.get("role") == "assistant" and m.get("tool_calls"):
                for tc in m["tool_calls"]:
                    fn = tc.get("function", {})
                    sig = (fn.get("name"), str(fn.get("arguments")))
                    if sig == last_sig and fn.get("name") != "compile_and_test":
                        flags.append("duplicate_tool_call")
                    last_sig = sig
            elif m.get("role") == "tool" and "ERROR:" in (m.get("content") or ""):
                edit_errors += 1
        if edit_errors >= 2:
            flags.append(f"tool_errors({edit_errors})")

        audit_entry = {
            "row": idx,
            "model": model,
            "lang": lang,
            "turns": turns,
            "critic_rejections": rejections,
            "approved": is_approved,
            "files": src_files,
            "added": added,
            "removed": removed,
            "flags": sorted(set(flags)),
            "record": rec,
        }
        row_audits.append(audit_entry)
        if audit_entry["flags"]:
            flagged.append(audit_entry)

    return {
        "total": len(rows),
        "approved": len(approved_rows),
        "rejected": rejected_count,
        "by_model": by_model,
        "by_lang": by_lang,
        "row_audits": row_audits,
        "flagged": flagged,
    }


def select_audit_samples(row_audits: list[dict[str, Any]], seed: int | None = None) -> list[dict[str, Any]]:
    """Select 2 random approved rows, ensuring at least 1 qwen3:14b CPP/CMake row if present."""
    approved = [r for r in row_audits if r["approved"]]
    if not approved:
        return []

    rng = random.Random(seed)
    cpp_14b = [r for r in approved if r["model"] == "qwen3:14b" and r["lang"] == "CPP"]
    chosen: list[dict[str, Any]] = []
    if cpp_14b:
        first = rng.choice(cpp_14b)
        chosen.append(first)
        remaining = [r for r in approved if r["row"] != first["row"]]
        if remaining:
            chosen.append(rng.choice(remaining))
    else:
        chosen = rng.sample(approved, k=min(2, len(approved)))
    return chosen


def generate_audit_packet(
    trajectories_path: str,
    out_path: str,
    seed: int | None = None,
) -> str:
    """Build AUDIT_PACKET.md from trajectories.jsonl and write to out_path."""
    if not os.path.isfile(trajectories_path):
        raise FileNotFoundError(f"Trajectories file not found: {trajectories_path}")

    rows: list[dict[str, Any]] = []
    with open(trajectories_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))

    stats = analyze_trajectories(rows)
    samples = select_audit_samples(stats["row_audits"], seed=seed)

    lines: list[str] = [
        "# RLVR Audit Packet",
        "",
        f"- **Generated (UTC):** {datetime.now(timezone.utc).isoformat()}",
        f"- **Source:** `{os.path.basename(trajectories_path)}`",
        f"- **Total Trajectories:** `{stats['total']}` (`approved={stats['approved']}`, `rejected={stats['rejected']}`)",
        f"- **By Model:** `{json.dumps(stats['by_model'], sort_keys=True)}`",
        f"- **By Language (`C` / `CPP` / `KT`):** `{json.dumps(stats['by_lang'], sort_keys=True)}`",
        f"- **Sanity Check Flags:** `{len(stats['flagged'])}` flagged row(s) out of `{stats['total']}`",
        "",
        "## 1. Per-Row Diff & Sanity Audit",
        "",
        "| Row | Model | Lang | Turns | Rej | Approved | Modified Files | + / - | Flags |",
        "| ---: | :--- | :---: | ---: | ---: | :---: | :--- | :---: | :--- |",
    ]

    for r in stats["row_audits"]:
        files_str = ", ".join(f"`{p}`" for p in r["files"]) if r["files"] else "*(none)*"
        flags_str = ", ".join(r["flags"]) if r["flags"] else "OK"
        lines.append(
            f"| {r['row']} | `{r['model']}` | {r['lang']} | {r['turns']} | {r['critic_rejections']} "
            f"| {'YES' if r['approved'] else 'NO'} | {files_str} | +{r['added']}/-{r['removed']} | {flags_str} |"
        )

    lines.extend(["", "## 2. Eval Benchmark Snapshots", ""])
    found_eval = False
    base_dir = os.path.dirname(os.path.abspath(trajectories_path))
    for eval_name in ("eval_results.json", "eval_results_domain.json"):
        eval_path = os.path.join(base_dir, eval_name)
        if not os.path.isfile(eval_path):
            continue
        found_eval = True
        with open(eval_path, "r", encoding="utf-8") as ef:
            summaries = json.load(ef)
        lines.extend([
            f"### `{eval_name}`",
            "",
            "| Model | Pass Rate | Avg Turns | Avg Time | Total Time |",
            "| :--- | ---: | ---: | ---: | ---: |",
        ])
        for s in summaries:
            lines.append(
                f"| `{s['model']}` | {s['passed']}/{s['total']} ({s['pass_rate_pct']}%) "
                f"| {s['avg_turns']} | {s['avg_sec']}s | {s['total_sec']}s |"
            )
        lines.append("")
    if not found_eval:
        lines.append("*(No `eval_results*.json` found alongside trajectories.)*")

    lines.extend(["", "## 3. Random Sampled Approved Trajectories (Raw Proof)", ""])
    for s in samples:
        rec = s["record"]
        trace = extract_tool_trace(rec.get("messages", []))
        lines.extend([
            f"### Sample Row {s['row']} — `{s['model']}` ({s['lang']})",
            f"- **Spec:** {rec.get('spec', '')}",
            f"- **Turns:** `{s['turns']}` | **Critic Rejections:** `{s['critic_rejections']}`",
            f"- **Critic Verdict:** {rec.get('critic_verdict', '').strip()}",
            "",
            "**`git_diff`:**",
            "```diff",
            (rec.get("git_diff") or "").rstrip(),
            "```",
            "",
            "**Tool Call Trace:**",
            "```json",
            json.dumps(trace, indent=2, ensure_ascii=False),
            "```",
            "",
        ])

    lines.extend([
        "---",
        "## External Auditor Instructions",
        "Inspect the per-row diff audit and sampled trajectories above for reward hacking, schema drift, or overfitting.",
        "Reply with either:",
        "- `AUDIT_VERDICT: APPROVED`",
        "- `AUDIT_VERDICT: REJECTED` followed by exact remediation instructions.",
        "",
    ])

    report = "\n".join(lines)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report)
    return report


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(description="Generate AUDIT_PACKET.md from trajectories.jsonl and copy to clipboard")
    parser.add_argument("--input", default=os.path.join(here, "trajectories.jsonl"), help="Path to trajectories.jsonl")
    parser.add_argument("--out", default=os.path.join(here, "AUDIT_PACKET.md"), help="Output markdown path")
    parser.add_argument("--seed", type=int, default=None, help="Optional PRNG seed for sample selection")
    parser.add_argument("--no-pbcopy", action="store_true", help="Skip macOS pbcopy clipboard copy")
    args = parser.parse_args()

    report = generate_audit_packet(args.input, args.out, seed=args.seed)
    print(f"[Audit] Generated {args.out} ({len(report)} chars)", flush=True)
    if not args.no_pbcopy and shutil.which("pbcopy"):
        subprocess.run(["pbcopy"], input=report.encode("utf-8"), check=True)
        print("[Audit] Copied AUDIT_PACKET.md to macOS clipboard via pbcopy", flush=True)


if __name__ == "__main__":
    main()
