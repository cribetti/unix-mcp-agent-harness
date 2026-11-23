import json
import os
import py_compile
import subprocess
import sys
import tempfile
import unittest

import eval as eval_harness
import mcp_server
import orchestrator
import rlvr_mlx

HARNESS_DIR = os.path.dirname(os.path.abspath(__file__))
MCP_SERVER = os.path.join(HARNESS_DIR, "mcp_server.py")
ORCHESTRATOR = os.path.join(HARNESS_DIR, "orchestrator.py")


class TestHarness(unittest.TestCase):
    def test_py_compile(self):
        py_compile.compile(MCP_SERVER, doraise=True)
        py_compile.compile(ORCHESTRATOR, doraise=True)

    def test_mcp_stdio_initialize_tools_and_path_jail(self):
        with tempfile.TemporaryDirectory() as td:
            requests = "\n".join([
                json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
                json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
                json.dumps({
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "read_file", "arguments": {"path": "../../etc/passwd"}},
                }),
            ]) + "\n"

            proc = subprocess.run(
                [sys.executable, MCP_SERVER, "--workspace", td],
                input=requests,
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            )
            lines = [json.loads(line) for line in proc.stdout.strip().splitlines()]
            self.assertEqual(len(lines), 3)

            self.assertEqual(lines[0]["id"], 1)
            self.assertEqual(lines[0]["result"]["serverInfo"]["name"], "unix-sandbox-mcp")

            self.assertEqual(lines[1]["id"], 2)
            tool_names = {t["name"] for t in lines[1]["result"]["tools"]}
            self.assertEqual(
                tool_names,
                {"find_files", "grep_search", "read_file", "edit_file", "write_file", "compile_and_test", "git_diff"},
            )

            self.assertEqual(lines[2]["id"], 3)
            self.assertEqual(lines[2]["error"]["code"], -32000)
            self.assertIn("escapes workspace", lines[2]["error"]["message"])

    def test_mcp_symlink_escape_blocked(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as outside:
            secret = os.path.join(outside, "secret.txt")
            with open(secret, "w", encoding="utf-8") as f:
                f.write("top-secret\n")
            os.symlink(secret, os.path.join(td, "leak.txt"))

            mcp = orchestrator.MCPClient(MCP_SERVER, workspace=td)
            try:
                with self.assertRaises(RuntimeError) as ctx:
                    mcp.call_tool("read_file", {"path": "leak.txt"})
                self.assertIn("escapes workspace", str(ctx.exception))
            finally:
                mcp.close()

    def test_mcp_client_non_destructive_workspace_and_tools(self):
        with tempfile.TemporaryDirectory() as td:
            sentinel = os.path.join(td, "keep_me.txt")
            with open(sentinel, "w", encoding="utf-8") as f:
                f.write("alpha\nbeta\ngamma\n")

            mcp = orchestrator.MCPClient(MCP_SERVER, workspace=td)
            try:
                self.assertIn("keep_me.txt", mcp.call_tool("find_files", {"pattern": "*.txt"}))
                self.assertIn("keep_me.txt:2:beta", mcp.call_tool("grep_search", {"query": "beta"}))
                self.assertIn("2: beta", mcp.call_tool("read_file", {"path": "keep_me.txt"}))

                edit_out = mcp.call_tool("edit_file", {"path": "keep_me.txt", "old_str": "beta", "new_str": "BETA"})
                self.assertIn("Edited keep_me.txt successfully", edit_out)
                self.assertIn("2: BETA", mcp.call_tool("read_file", {"path": "keep_me.txt"}))

                mcp.call_tool("write_file", {"path": "sub/new.txt", "content": "hello\n"})
                self.assertTrue(os.path.exists(sentinel))
                self.assertTrue(os.path.exists(os.path.join(td, "sub", "new.txt")))
            finally:
                mcp.close()

    def test_mcp_git_diff_with_single_untracked_kt_file(self):
        with tempfile.TemporaryDirectory() as td:
            subprocess.run(
                "git init -q && git config user.email 't@local' && git config user.name 'T' && git commit --allow-empty -m 'init' -q",
                shell=True,
                cwd=td,
                check=True,
            )
            mcp = orchestrator.MCPClient(MCP_SERVER, workspace=td)
            try:
                mcp.call_tool("write_file", {"path": "Main.kt", "content": "fun main() { println(\"hi\") }\n"})
                diff = mcp.call_tool("git_diff", {})
                self.assertIn("Main.kt", diff)
                self.assertIn("println", diff)
            finally:
                mcp.close()

    def test_agents_md_and_task_resolution(self):
        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "AGENTS.md"), "w", encoding="utf-8") as f:
                f.write("# Rules\nUse ReentrantLock.\n")
            task_file = os.path.join(td, "task.txt")
            with open(task_file, "w", encoding="utf-8") as f:
                f.write("Implement feature X\n")

            self.assertIn("Use ReentrantLock.", orchestrator.load_agents_md(td))
            self.assertEqual(orchestrator.load_agents_md(os.path.join(td, "missing")), "")
            self.assertEqual(orchestrator.resolve_task_spec(task_file, None), "Implement feature X")
            self.assertEqual(orchestrator.resolve_task_spec("inline spec", None), "inline spec")
            self.assertEqual(orchestrator.resolve_task_spec(None, "pos spec"), "pos spec")
            self.assertEqual(orchestrator.resolve_task_spec(None, None), orchestrator.DEFAULT_SPEC)

    def test_log_trajectory_jsonl(self):
        with tempfile.TemporaryDirectory() as td:
            log_path = os.path.join(td, "nested", "trajectories.jsonl")
            orchestrator.log_trajectory(
                log_path,
                model="qwen2.5-coder:7b",
                workspace=td,
                spec="Test spec",
                messages=[{"role": "user", "content": "Test spec"}],
                git_diff="diff --git a/a.kt b/a.kt",
                critic_verdict="APPROVED: looks good",
                turns=2,
                critic_rejections=0,
            )
            orchestrator.log_trajectory(
                log_path,
                model="qwen3:8b",
                workspace=td,
                spec="Test spec 2",
                messages=[{"role": "user", "content": "Test spec 2"}],
                git_diff="diff --git a/b.kt b/b.kt",
                critic_verdict="APPROVED: ok",
                turns=3,
                critic_rejections=1,
            )
            with open(log_path, "r", encoding="utf-8") as f:
                rows = [json.loads(line) for line in f.read().splitlines()]
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["model"], "qwen2.5-coder:7b")
            self.assertEqual(rows[0]["turns"], 2)
            self.assertIn("timestamp", rows[0])
            self.assertEqual(rows[1]["critic_rejections"], 1)

    def test_rlvr_mlx_export(self):
        with tempfile.TemporaryDirectory() as td:
            traj_path = os.path.join(td, "trajectories.jsonl")
            out_dir = os.path.join(td, "mlx_data")
            sample_msgs = [
                {"role": "system", "content": "You are a systems engineer."},
                {"role": "user", "content": "Write Main.kt"},
                {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {"id": "c1", "type": "function", "function": {"name": "write_file", "arguments": "{\"path\": \"Main.kt\"}"}}
                    ],
                },
                {"role": "tool", "tool_call_id": "c1", "content": "Wrote Main.kt"},
            ]
            with open(traj_path, "w", encoding="utf-8") as f:
                for i in range(3):
                    f.write(json.dumps({"spec": f"task {i}", "messages": sample_msgs}) + "\n")

            n_train, n_valid = rlvr_mlx.export_mlx_dataset(traj_path, out_dir, val_split=0.2)
            self.assertEqual((n_train, n_valid), (2, 1))
            with open(os.path.join(out_dir, "train.jsonl"), "r", encoding="utf-8") as f:
                row = json.loads(f.readline())
            self.assertEqual(len(row["messages"]), 4)
            self.assertIn("write_file", row["messages"][2]["content"])

    def test_eval_harness_parsing_and_summary(self):
        sample_stdout = (
            "=== [Coder Turn 1 | qwen2.5-coder:7b] ===\n"
            "=== [Coder Turn 2 | qwen2.5-coder:7b] ===\n"
            "=== APPROVED BY CRITIC & VERIFIED EXIT 0 ===\n"
        )
        passed, turns = eval_harness.parse_orchestrator_output(sample_stdout)
        self.assertTrue(passed)
        self.assertEqual(turns, 2)

        summary = eval_harness.summarize_results(
            "qwen2.5-coder:7b",
            [
                {"id": "t1", "passed": True, "turns": 2, "elapsed_sec": 30.0},
                {"id": "t2", "passed": False, "turns": 8, "elapsed_sec": 90.0},
            ],
        )
        self.assertEqual(summary["passed"], 1)
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["pass_rate_pct"], 50.0)
        table = eval_harness.format_summary_table([summary])
        self.assertIn("1/2 (50.0%)", table)
        self.assertEqual(len(eval_harness.load_eval_tasks(None)), 6)

    def test_mcp_docker_sandbox_command_builder(self):
        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "main.c"), "w", encoding="utf-8") as f:
                f.write("int main(void) { return 0; }\n")
            cmd, timeout = mcp_server.build_test_command(td, sandbox="docker")
            self.assertEqual(cmd[:4], ["docker", "run", "--rm", "--network=none"])
            self.assertIn(f"{td}:/workspace", cmd)
            self.assertIn("gcc:14", cmd)
            self.assertEqual(timeout, 30)


if __name__ == "__main__":
    unittest.main()
