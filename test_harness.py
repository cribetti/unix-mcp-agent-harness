import json
import os
import py_compile
import subprocess
import sys
import tempfile
import unittest

import eval as eval_harness
import generate_tasks
import harvest_rlvr
import mcp_server
import orchestrator
import rlvr_mlx

HARNESS_DIR = os.path.dirname(os.path.abspath(__file__))
MCP_SERVER = os.path.join(HARNESS_DIR, "mcp_server.py")
ORCHESTRATOR = os.path.join(HARNESS_DIR, "orchestrator.py")


class TestHarness(unittest.TestCase):
    def test_py_compile(self):
        for fname in ("mcp_server.py", "orchestrator.py", "rlvr_mlx.py", "eval.py", "generate_tasks.py", "harvest_rlvr.py"):
            py_compile.compile(os.path.join(HARNESS_DIR, fname), doraise=True)

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
                self.assertIn("keep_me.txt", mcp.call_tool("find_files", {"pattern": "*.md *.txt"}))
                self.assertIn("keep_me.txt", mcp.call_tool("find_files", {"pattern": "*.nonexistent"}))
                self.assertIn("keep_me.txt:2:beta", mcp.call_tool("grep_search", {"query": "beta"}))
                self.assertIn("2: beta", mcp.call_tool("read_file", {"path": "keep_me.txt"}))

                edit_out = mcp.call_tool("edit_file", {"path": "keep_me.txt", "old_str": "beta", "new_str": "BETA"})
                self.assertIn("Edited keep_me.txt successfully", edit_out)
                self.assertIn("2: BETA", mcp.call_tool("read_file", {"path": "keep_me.txt"}))

                mcp.call_tool("write_file", {"path": "Indented.kt", "content": "fun f() {\n    val x = 1\n    val y = 2\n}\n"})
                indent_edit = mcp.call_tool(
                    "edit_file",
                    {"path": "Indented.kt", "old_str": "val x = 1\nval y = 2", "new_str": "val x = 10\nval y = 20"},
                )
                self.assertIn("Edited Indented.kt successfully", indent_edit)
                self.assertIn("    val x = 10", mcp.call_tool("read_file", {"path": "Indented.kt"}))

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
                    "content": '{"name": "write_file", "arguments": {"path": "Main.kt"}}',
                    "tool_calls": [
                        {"id": "c1", "type": "function", "function": {"name": "write_file", "arguments": "{\"path\": \"Main.kt\"}"}}
                    ],
                },
                {"role": "tool", "tool_call_id": "c1", "content": "Wrote Main.kt"},
            ]
            with open(traj_path, "w", encoding="utf-8") as f:
                # Legacy row without diff should be filtered out by default
                f.write(json.dumps({"spec": "legacy", "git_diff": "No changes.", "messages": sample_msgs}) + "\n")
                for i in range(3):
                    f.write(json.dumps({"spec": f"task {i}", "git_diff": "diff --git a/Main.kt b/Main.kt", "messages": sample_msgs}) + "\n")

            n_train, n_valid = rlvr_mlx.export_mlx_dataset(traj_path, out_dir, val_split=0.2)
            self.assertEqual((n_train, n_valid), (2, 1))
            with open(os.path.join(out_dir, "train.jsonl"), "r", encoding="utf-8") as f:
                row = json.loads(f.readline())
            self.assertEqual(len(row["messages"]), 4)
            self.assertIn("tools", row)
            self.assertEqual(len(row["tools"]), len(mcp_server.TOOLS))
            assistant_msg = row["messages"][2]
            self.assertEqual(assistant_msg["content"], "")
            self.assertEqual(assistant_msg["tool_calls"][0]["function"]["name"], "write_file")
            self.assertEqual(assistant_msg["tool_calls"][0]["function"]["arguments"], {"path": "Main.kt"})

    def test_modelfile_parity(self):
        modelfile_path = os.path.join(HARNESS_DIR, "Modelfile.custom")
        self.assertTrue(os.path.isfile(modelfile_path))
        with open(modelfile_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertTrue(content.startswith("FROM "))
        self.assertEqual(content.split("\n", 1)[1], rlvr_mlx.render_modelfile().split("\n", 1)[1])
        for marker in (
            "<|im_start|>system",
            "<tools>",
            "<tool_call>",
            "<tool_response>",
            "<|im_end|>",
            "SYSTEM You are Qwen, created by Alibaba Cloud. You are a helpful assistant.",
            'PARAMETER stop "<|im_end|>"',
        ):
            self.assertIn(marker, content)

    def test_generate_tasks_deterministic_and_loadable(self):
        tasks_a = generate_tasks.generate_tasks(count=120, seed=42)
        tasks_b = generate_tasks.generate_tasks(count=120, seed=42)
        self.assertEqual(tasks_a, tasks_b)
        self.assertEqual(len(tasks_a), 120)
        self.assertEqual(len({t["id"] for t in tasks_a}), 120)
        self.assertEqual(len({t["spec"] for t in tasks_a}), 120)
        self.assertEqual(
            {t["category"] for t in tasks_a},
            {"kotlin_concurrency", "ndk_cpp_cmake", "owasp_masvs", "c_systems"},
        )
        with tempfile.TemporaryDirectory() as td:
            tasks_json = os.path.join(td, "tasks.json")
            with open(tasks_json, "w", encoding="utf-8") as f:
                json.dump(tasks_a, f)
            loaded = eval_harness.load_eval_tasks(tasks_json)
            self.assertEqual(len(loaded), 120)

    def test_generated_workspace_tasks_fail_baseline_compile_and_test(self):
        tasks = generate_tasks.generate_tasks(count=16, seed=42)
        by_cat = {}
        for t in tasks:
            if t.get("workspace_files") and t["category"] not in by_cat:
                by_cat[t["category"]] = t
        self.assertEqual(set(by_cat.keys()), {"kotlin_concurrency", "ndk_cpp_cmake", "owasp_masvs"})

        for cat, task in by_cat.items():
            with tempfile.TemporaryDirectory() as td:
                eval_harness.materialize_workspace(td, task["workspace_files"])
                cmd, timeout = mcp_server.build_test_command(td, sandbox="host")
                res = subprocess.run(cmd, cwd=td, capture_output=True, text=True, timeout=timeout)
                self.assertNotEqual(res.returncode, 0, f"Baseline for {cat} ({task['id']}) unexpectedly passed!")

    def test_harvest_rlvr_helpers(self):
        with tempfile.TemporaryDirectory() as td:
            traj = os.path.join(td, "trajectories.jsonl")
            with open(traj, "w", encoding="utf-8") as f:
                f.write(json.dumps({"spec": "old_spec", "git_diff": "No changes.", "messages": []}) + "\n")
                f.write(json.dumps({"spec": "good_spec", "git_diff": "diff --git a/x b/x", "messages": []}) + "\n")

            self.assertEqual(harvest_rlvr.load_existing_specs(traj), {"good_spec"})
            kept, removed = harvest_rlvr.purge_legacy_trajectories(traj)
            self.assertEqual((kept, removed), (1, 1))
            self.assertTrue(os.path.isfile(traj + ".bak"))
            self.assertEqual(harvest_rlvr.load_existing_specs(traj), {"good_spec"})

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

    def test_mcp_cmake_ctest_execution(self):
        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "CMakeLists.txt"), "w", encoding="utf-8") as f:
                f.write(
                    "cmake_minimum_required(VERSION 3.16)\n"
                    "project(smoke LANGUAGES CXX)\n"
                    "set(CMAKE_CXX_STANDARD 17)\n"
                    "enable_testing()\n"
                    "add_executable(smoke_test main.cpp)\n"
                    "add_test(NAME smoke COMMAND smoke_test)\n"
                )
            with open(os.path.join(td, "main.cpp"), "w", encoding="utf-8") as f:
                f.write("#include <cassert>\nint main() { assert(1 + 1 == 2); return 0; }\n")
            mcp = orchestrator.MCPClient(MCP_SERVER, workspace=td)
            try:
                out = mcp.call_tool("compile_and_test", {})
                self.assertIn("EXIT_CODE: 0", out)
            finally:
                mcp.close()


if __name__ == "__main__":
    unittest.main()
