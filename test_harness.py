import json
import os
import py_compile
import subprocess
import sys
import tempfile
import unittest

import orchestrator

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


if __name__ == "__main__":
    unittest.main()
