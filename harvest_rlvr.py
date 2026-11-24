import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

from eval import materialize_workspace, parse_orchestrator_output
from generate_tasks import generate_tasks


def load_existing_specs(trajectories_path: str) -> set[str]:
    """Return specs already logged with a non-empty git_diff in trajectories.jsonl."""
    if not os.path.isfile(trajectories_path):
        return set()
    seen: set[str] = set()
    with open(trajectories_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("git_diff") != "No changes." and rec.get("spec"):
                seen.add(rec["spec"])
    return seen


def purge_legacy_trajectories(trajectories_path: str) -> tuple[int, int]:
    """Remove legacy rows with 'git_diff == No changes.' (creating a .bak backup). Returns (kept, removed)."""
    if not os.path.isfile(trajectories_path):
        return 0, 0
    kept_lines: list[str] = []
    removed = 0
    with open(trajectories_path, "r", encoding="utf-8") as f:
        for line in f:
            raw = line.strip()
            if not raw:
                continue
            rec = json.loads(raw)
            if rec.get("git_diff") == "No changes.":
                removed += 1
            else:
                kept_lines.append(raw)
    if removed > 0:
        shutil.copy2(trajectories_path, trajectories_path + ".bak")
        with open(trajectories_path, "w", encoding="utf-8") as f:
            for item in kept_lines:
                f.write(item + "\n")
    return len(kept_lines), removed


def build_orchestrator_cmd(
    orchestrator_script: str,
    task: dict,
    *,
    model: str,
    max_turns: int,
    sandbox: str,
    trajectories_path: str,
    workspace_dir: str | None = None,
) -> list[str]:
    """Build the subprocess command to execute orchestrator.py for a single task."""
    cmd = [
        sys.executable,
        orchestrator_script,
        "--model",
        model,
        "--max-turns",
        str(max_turns),
        "--sandbox",
        sandbox,
        "--trajectories",
        trajectories_path,
        "--task",
        task["spec"],
    ]
    if workspace_dir:
        cmd.extend(["--workspace", workspace_dir])
    return cmd


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(
        description="Batch-harvest Critic-approved (EXIT_CODE: 0) RLVR trajectories into trajectories.jsonl"
    )
    parser.add_argument(
        "--tasks-file",
        default=os.path.join(here, "generated_tasks.json"),
        help="Input JSON tasks file from generate_tasks.py (auto-generated if --generate is set)",
    )
    parser.add_argument("--generate", action="store_true", help="Generate tasks on the fly if --tasks-file is missing")
    parser.add_argument("--count", type=int, default=120, help="Task count if --generate is used (default: 120)")
    parser.add_argument("--seed", type=int, default=42, help="Seed if --generate is used (default: 42)")
    parser.add_argument("--model", default="qwen2.5-coder:7b", help="Ollama model to harvest trajectories from")
    parser.add_argument("--sandbox", choices=["host", "docker"], default="host", help="compile_and_test sandbox mode")
    parser.add_argument("--max-turns", type=int, default=16, help="Max Coder turns per task (default: 16)")
    parser.add_argument("--timeout", type=int, default=150, help="Per-task timeout in seconds (default: 150)")
    parser.add_argument("--category", default=None, help="Filter tasks to one category (e.g., owasp_masvs)")
    parser.add_argument("--offset", type=int, default=0, help="Start task index (default: 0)")
    parser.add_argument("--limit", type=int, default=None, help="Max number of tasks to run in this batch")
    parser.add_argument(
        "--trajectories",
        default=os.path.join(here, "trajectories.jsonl"),
        help="Destination trajectories JSONL path",
    )
    parser.add_argument("--no-skip-existing", action="store_true", help="Re-run tasks already present in trajectories.jsonl")
    parser.add_argument("--purge-legacy", action="store_true", help="Remove legacy rows with git_diff == 'No changes.' first")
    args = parser.parse_args()

    if args.purge_legacy:
        kept, removed = purge_legacy_trajectories(args.trajectories)
        print(f"[Harvest] Purged {removed} legacy no-diff trajectories (kept {kept})", flush=True)

    if os.path.isfile(args.tasks_file):
        with open(args.tasks_file, "r", encoding="utf-8") as f:
            tasks = json.load(f)
    elif args.generate:
        tasks = generate_tasks(count=args.count, seed=args.seed)
        with open(args.tasks_file, "w", encoding="utf-8") as f:
            json.dump(tasks, f, indent=2)
        print(f"[Harvest] Generated {len(tasks)} tasks -> {args.tasks_file}", flush=True)
    else:
        print(f"ERROR: Tasks file not found: {args.tasks_file} (pass --generate or run generate_tasks.py)", file=sys.stderr)
        sys.exit(1)

    if args.category:
        tasks = [t for t in tasks if t.get("category") == args.category]
    tasks = tasks[args.offset :]
    if args.limit is not None:
        tasks = tasks[: args.limit]

    existing_specs = set() if args.no_skip_existing else load_existing_specs(args.trajectories)
    orchestrator_script = os.path.join(here, "orchestrator.py")

    approved_count = 0
    failed_count = 0
    timeout_count = 0
    skipped_count = 0

    print(
        f"[Harvest] Running {len(tasks)} tasks | model={args.model} | sandbox={args.sandbox} | out={args.trajectories}",
        flush=True,
    )

    for idx, task in enumerate(tasks, 1):
        task_id = task.get("id", f"task_{idx}")
        if task["spec"] in existing_specs:
            skipped_count += 1
            print(f"  [{idx}/{len(tasks)}] {task_id}: SKIPPED (already harvested)", flush=True)
            continue

        t0 = time.perf_counter()
        ws_cm = None
        ws_dir = None
        try:
            if task.get("workspace_files"):
                ws_cm = tempfile.TemporaryDirectory()
                ws_dir = materialize_workspace(ws_cm.name, task["workspace_files"])
            cmd = build_orchestrator_cmd(
                orchestrator_script,
                task,
                model=args.model,
                max_turns=args.max_turns,
                sandbox=args.sandbox,
                trajectories_path=args.trajectories,
                workspace_dir=ws_dir,
            )
            try:
                res = subprocess.run(
                    cmd,
                    cwd=here,
                    capture_output=True,
                    text=True,
                    timeout=args.timeout,
                )
                passed, turns = parse_orchestrator_output(res.stdout)
                timed_out = False
            except subprocess.TimeoutExpired as exc:
                stdout = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
                _, turns = parse_orchestrator_output(stdout)
                passed = False
                timed_out = True
        finally:
            if ws_cm is not None:
                ws_cm.cleanup()

        dt = time.perf_counter() - t0
        if passed:
            approved_count += 1
            existing_specs.add(task["spec"])
            status = "APPROVED"
        elif timed_out:
            timeout_count += 1
            status = "TIMEOUT"
        else:
            failed_count += 1
            status = "FAILED"
        print(f"  [{idx}/{len(tasks)}] {task_id}: {status} (turns={turns}, {dt:.1f}s)", flush=True)

    print(
        f"\n[Harvest Summary] approved={approved_count} failed={failed_count} "
        f"timed_out={timeout_count} skipped={skipped_count}",
        flush=True,
    )


if __name__ == "__main__":
    main()
