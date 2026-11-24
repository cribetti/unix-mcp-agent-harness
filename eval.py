import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time

DEFAULT_EVAL_TASKS = [
    {
        "id": "c_bounded_queue",
        "spec": (
            "Create `bqueue.c` implementing a thread-safe bounded integer queue with `pthread_mutex_t` "
            "and `pthread_cond_t`, plus a `main()` with 2 producer and 2 consumer threads verifying "
            "all 200 items sum correctly with `assert`, printing 'ALL TESTS PASSED'."
        ),
    },
    {
        "id": "c_rw_counter",
        "spec": (
            "Create `rw_counter.c` implementing a thread-safe counter with `pthread_rwlock_t` and a `main()` "
            "spawning 4 writer threads (250 increments each) and 4 reader threads verifying final count == 1000 "
            "with `assert`, printing 'ALL TESTS PASSED'."
        ),
    },
    {
        "id": "c_bitset_lock",
        "spec": (
            "Create `bitset.c` implementing a thread-safe 64-bit bitset with `pthread_mutex_t` (set, clear, test) "
            "and a `main()` spawning 4 threads setting distinct bits and asserting all bits set, printing 'ALL TESTS PASSED'."
        ),
    },
    {
        "id": "kt_rate_window",
        "spec": (
            "Create `Main.kt` implementing a thread-safe `SlidingCounter` (max 5 events per window) using `ReentrantLock` "
            "(`try { ... } finally { lock.unlock() }`), and in `main()` use `Thread { ... }` and `assert(condition)` "
            "(do NOT import `kotlin.test`) to test 4 threads, printing 'ALL TESTS PASSED'."
        ),
    },
    {
        "id": "kt_event_count",
        "spec": (
            "Create `Main.kt` implementing a thread-safe `EventCounter` map using `ReentrantLock` "
            "(`try { ... } finally { lock.unlock() }`), and in `main()` use `Thread { ... }` and `assert(condition)` "
            "(do NOT import `kotlin.test`) to verify 6 threads x 100 events == 600, printing 'ALL TESTS PASSED'."
        ),
    },
    {
        "id": "kt_bounded_pool",
        "spec": (
            "Create `Main.kt` implementing a thread-safe `IntPool` (capacity 4) using `ReentrantLock` and `Condition` "
            "(`try { ... } finally { lock.unlock() }`), and in `main()` use `Thread { ... }` and `assert(condition)` "
            "(do NOT import `kotlin.test`) to verify acquire/release across 6 threads, printing 'ALL TESTS PASSED'."
        ),
    },
]


def load_eval_tasks(tasks_file: str | None) -> list[dict]:
    """Load held-out eval tasks from JSON file or return DEFAULT_EVAL_TASKS."""
    if not tasks_file:
        return list(DEFAULT_EVAL_TASKS)
    with open(tasks_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("Tasks file must be a JSON list of {id, spec} objects or strings")
    tasks = []
    for idx, item in enumerate(data, 1):
        if isinstance(item, str):
            tasks.append({"id": f"task_{idx}", "spec": item})
        elif isinstance(item, dict) and "spec" in item:
            entry = {"id": item.get("id", f"task_{idx}"), "spec": item["spec"]}
            if isinstance(item.get("workspace_files"), dict):
                entry["workspace_files"] = item["workspace_files"]
            tasks.append(entry)
        else:
            raise ValueError(f"Invalid task entry at index {idx - 1}")
    return tasks


def materialize_workspace(workspace_dir: str, workspace_files: dict[str, str]) -> str:
    """Populate a temporary git-initialized workspace for workspace-backed eval/harvest tasks."""
    os.makedirs(workspace_dir, exist_ok=True)
    for rel_path, content in workspace_files.items():
        norm = os.path.normpath(rel_path)
        if os.path.isabs(norm) or norm.startswith(".."):
            raise ValueError(f"Invalid workspace_files path: {rel_path}")
        full_path = os.path.join(workspace_dir, norm)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(content)
    subprocess.run(
        "git init -q && git config user.email 'agent@local' && git config user.name 'Agent' "
        "&& git add -A && git commit --allow-empty -m 'baseline' -q",
        shell=True,
        cwd=workspace_dir,
        check=True,
    )
    return workspace_dir


def parse_orchestrator_output(stdout: str) -> tuple[bool, int]:
    """Return (approved, turns_used) from orchestrator stdout."""
    approved = "=== APPROVED BY CRITIC & VERIFIED EXIT 0 ===" in stdout
    turns = len(re.findall(r"=== \[Coder Turn \d+ \|", stdout))
    return approved, turns


def summarize_results(model: str, runs: list[dict]) -> dict:
    """Compute pass rate, average turns, and total time for a model's eval runs."""
    total = len(runs)
    passed = sum(1 for r in runs if r["passed"])
    pass_rate = (passed / total * 100.0) if total else 0.0
    avg_turns = (sum(r["turns"] for r in runs) / total) if total else 0.0
    total_sec = sum(r["elapsed_sec"] for r in runs)
    avg_sec = (total_sec / total) if total else 0.0
    return {
        "model": model,
        "passed": passed,
        "total": total,
        "pass_rate_pct": round(pass_rate, 1),
        "avg_turns": round(avg_turns, 2),
        "avg_sec": round(avg_sec, 1),
        "total_sec": round(total_sec, 1),
        "runs": runs,
    }


def format_summary_table(summaries: list[dict]) -> str:
    """Format model summaries as a Markdown comparison table."""
    lines = [
        "| Model | Pass Rate | Avg Turns | Avg Time | Total Time |",
        "| :--- | ---: | ---: | ---: | ---: |",
    ]
    for s in summaries:
        lines.append(
            f"| `{s['model']}` | {s['passed']}/{s['total']} ({s['pass_rate_pct']}%) "
            f"| {s['avg_turns']} | {s['avg_sec']}s | {s['total_sec']}s |"
        )
    return "\n".join(lines)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(description="Held-out Evaluation Harness for Local Models")
    parser.add_argument(
        "--models",
        nargs="+",
        default=["qwen2.5-coder:7b"],
        help="One or more Ollama model names to benchmark",
    )
    parser.add_argument("--tasks-file", default=None, help="Optional JSON file of held-out tasks")
    parser.add_argument("--max-turns", type=int, default=8, help="Max Coder turns per task (default: 8)")
    parser.add_argument("--timeout", type=int, default=150, help="Per-task timeout in seconds (default: 150)")
    parser.add_argument("--out", default=os.path.join(here, "eval_results.json"), help="Output JSON report path")
    args = parser.parse_args()

    tasks = load_eval_tasks(args.tasks_file)
    orchestrator_script = os.path.join(here, "orchestrator.py")
    summaries = []

    with tempfile.TemporaryDirectory() as td:
        temp_traj = os.path.join(td, "eval_trajectories.jsonl")
        for model in args.models:
            print(f"\n=== Evaluating {model} ({len(tasks)} held-out tasks) ===", flush=True)
            runs = []
            for idx, task in enumerate(tasks, 1):
                t0 = time.perf_counter()
                cmd = [
                    sys.executable,
                    orchestrator_script,
                    "--model",
                    model,
                    "--max-turns",
                    str(args.max_turns),
                    "--trajectories",
                    temp_traj,
                    "--task",
                    task["spec"],
                ]
                task_ws_cm = None
                if task.get("workspace_files"):
                    task_ws_cm = tempfile.TemporaryDirectory()
                    ws_dir = materialize_workspace(task_ws_cm.name, task["workspace_files"])
                    cmd.extend(["--workspace", ws_dir])
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
                    if task_ws_cm is not None:
                        task_ws_cm.cleanup()
                dt = time.perf_counter() - t0
                runs.append({
                    "id": task["id"],
                    "passed": passed,
                    "turns": turns,
                    "timed_out": timed_out,
                    "elapsed_sec": round(dt, 1),
                })
                status = "PASS" if passed else ("TIMEOUT" if timed_out else "FAIL")
                print(f"  [{idx}/{len(tasks)}] {task['id']}: {status} (turns={turns}, {dt:.1f}s)", flush=True)

            summaries.append(summarize_results(model, runs))

    print("\n" + format_summary_table(summaries), flush=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(summaries, f, indent=2)
    print(f"\n[Eval] Saved report to {args.out}", flush=True)


if __name__ == "__main__":
    main()
