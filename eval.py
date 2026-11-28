import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time

import providers

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


def run_security_gate(harness_dir: str | None = None, test_file: str = "test_redteam.py") -> tuple[bool, str]:
    """Run the adversarial red-team suite before eval benchmarks; return (passed, output)."""
    target_dir = harness_dir or os.path.dirname(os.path.abspath(__file__))
    test_path = os.path.join(target_dir, test_file)
    if not os.path.isfile(test_path):
        return False, f"Security gate test file not found: {test_path}"
    res = subprocess.run(
        [sys.executable, "-m", "unittest", test_file, "-v"],
        cwd=target_dir,
        capture_output=True,
        text=True,
        timeout=30,
    )
    output = (res.stdout + "\n" + res.stderr).strip()
    return res.returncode == 0, output


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(description="Held-out Evaluation Harness for Local Models")
    parser.add_argument(
        "--models",
        nargs="+",
        default=["qwen2.5-coder:7b"],
        help="One or more model names to benchmark",
    )
    parser.add_argument("--provider", default=None, help="LLM provider (env: LLM_PROVIDER; default: ollama)")
    parser.add_argument("--base-url", default=None, help="OpenAI-compatible endpoint URL (env: LLM_BASE_URL)")
    parser.add_argument("--api-key", default=None, help="Provider API key (env: LLM_API_KEY)")
    parser.add_argument("--config", default=None, help="Optional YAML provider config file (env: LLM_CONFIG)")
    parser.add_argument(
        "--audit-log",
        default="",
        help="Optional audit.jsonl compliance log path for eval runs (disabled by default)",
    )
    parser.add_argument("--tasks-file", default=None, help="Optional JSON file of held-out tasks")
    parser.add_argument("--max-turns", type=int, default=8, help="Max Coder turns per task (default: 8)")
    parser.add_argument("--timeout", type=int, default=150, help="Per-task timeout in seconds (default: 150)")
    parser.add_argument(
        "--security-gate",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Run adversarial red-team security suite before evaluation (default: enabled)",
    )
    parser.add_argument("--out", default=os.path.join(here, "eval_results.json"), help="Output JSON report path")
    args = parser.parse_args()

    if args.security_gate:
        print("=== [Security Gate] Running test_redteam.py ===", flush=True)
        gate_ok, gate_out = run_security_gate(here)
        if not gate_ok:
            print(f"[Security Gate] FAILED — aborting eval:\n{gate_out}", file=sys.stderr, flush=True)
            sys.exit(2)
        print("[Security Gate] PASSED (100% red-team refusal verified)", flush=True)

    tasks = load_eval_tasks(args.tasks_file)
    orchestrator_script = os.path.join(here, "orchestrator.py")
    summaries = []

    with tempfile.TemporaryDirectory() as td:
        temp_traj = os.path.join(td, "eval_trajectories.jsonl")
        for model in args.models:
            provider_cfg = providers.resolve_provider_config(
                provider=args.provider,
                base_url=args.base_url,
                api_key=args.api_key,
                model=model,
                config_path=args.config,
            )
            print(
                f"\n=== Evaluating {provider_cfg.model} (provider={provider_cfg.provider}, "
                f"base_url={provider_cfg.base_url}, {len(tasks)} held-out tasks) ===",
                flush=True,
            )
            child_env = os.environ.copy()
            child_env["LLM_PROVIDER"] = provider_cfg.provider
            child_env["LLM_BASE_URL"] = provider_cfg.base_url
            child_env["LLM_API_KEY"] = provider_cfg.api_key
            child_env["LLM_MODEL"] = provider_cfg.model
            runs = []
            for idx, task in enumerate(tasks, 1):
                t0 = time.perf_counter()
                cmd = [
                    sys.executable,
                    orchestrator_script,
                    "--provider",
                    provider_cfg.provider,
                    "--base-url",
                    provider_cfg.base_url,
                    "--model",
                    provider_cfg.model,
                    "--max-turns",
                    str(args.max_turns),
                    "--trajectories",
                    temp_traj,
                    "--audit-log",
                    args.audit_log,
                    "--task",
                    task["spec"],
                ]
                if args.config:
                    cmd.extend(["--config", args.config])
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
                        env=child_env,
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
