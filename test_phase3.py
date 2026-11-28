from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import py_compile
import subprocess
import sys
import tempfile
import threading
import unittest

import yaml

import audit_logger
import demo_showcase
import orchestrator
import providers

HARNESS_DIR = os.path.dirname(os.path.abspath(__file__))
DEPLOY_DIR = os.path.join(HARNESS_DIR, "deploy")
CONFIG_EXAMPLE = os.path.join(HARNESS_DIR, "config.example.yaml")
AUDIT_LOGGER_SCRIPT = os.path.join(HARNESS_DIR, "audit_logger.py")
MCP_SERVER_SCRIPT = os.path.join(HARNESS_DIR, "mcp_server.py")
ORCHESTRATOR_SCRIPT = os.path.join(HARNESS_DIR, "orchestrator.py")
EVAL_SCRIPT = os.path.join(HARNESS_DIR, "eval.py")


class _MockOpenAIHandler(BaseHTTPRequestHandler):
    captured_requests: list[dict] = []
    force_error_status: int | None = None

    def log_message(self, format, *args):  # noqa: A002 - silence test HTTP logs
        return

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length).decode("utf-8")
        body = json.loads(raw_body)
        self.__class__.captured_requests.append(
            {
                "path": self.path,
                "auth": self.headers.get("Authorization"),
                "api_key_header": self.headers.get("api-key"),
                "model": body.get("model"),
                "stream": body.get("stream"),
            }
        )

        if self.__class__.force_error_status is not None:
            status = self.__class__.force_error_status
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            auth_hdr = self.headers.get("Authorization", "")
            err_body = {
                "error": {
                    "message": f"Invalid credentials ({auth_hdr}) for enterprise gateway",
                    "type": "authentication_error",
                }
            }
            self.wfile.write(json.dumps(err_body).encode("utf-8"))
            return

        self.send_response(200)
        if body.get("stream"):
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            chunk1 = {
                "id": "chatcmpl-mock-1",
                "object": "chat.completion.chunk",
                "created": 1732800000,
                "model": body.get("model", "mock-model"),
                "choices": [{"index": 0, "delta": {"role": "assistant", "content": "APPROVED: "}, "finish_reason": None}],
            }
            chunk2 = {
                "id": "chatcmpl-mock-1",
                "object": "chat.completion.chunk",
                "created": 1732800000,
                "model": body.get("model", "mock-model"),
                "choices": [{"index": 0, "delta": {"content": "mock enterprise endpoint OK"}, "finish_reason": "stop"}],
            }
            payload = f"data: {json.dumps(chunk1)}\n\ndata: {json.dumps(chunk2)}\n\ndata: [DONE]\n\n"
            self.wfile.write(payload.encode("utf-8"))
        else:
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "id": "chatcmpl-mock-1",
                "object": "chat.completion",
                "created": 1732800000,
                "model": body.get("model", "mock-model"),
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "APPROVED: mock enterprise endpoint OK"},
                        "finish_reason": "stop",
                    }
                ],
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))


class TestPhase3EnterprisePackaging(unittest.TestCase):
    """Fast deterministic tests for Phase 3: providers, tamper-evident audit logs, and Docker hardening."""

    def test_01_py_compile_and_cli_flags(self):
        for fname in ("providers.py", "audit_logger.py", "mcp_server.py", "orchestrator.py", "eval.py"):
            py_compile.compile(os.path.join(HARNESS_DIR, fname), doraise=True)

        for script in (ORCHESTRATOR_SCRIPT, EVAL_SCRIPT):
            proc = subprocess.run(
                [sys.executable, script, "--help"],
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            )
            for flag in ("--provider", "--config", "--api-key", "--audit-log", "--base-url"):
                self.assertIn(flag, proc.stdout)

    def test_02_provider_config_routing_precedence_and_redaction(self):
        # 1. Default local Ollama
        default_cfg = providers.resolve_provider_config(env={})
        self.assertEqual(default_cfg.provider, "ollama")
        self.assertEqual(default_cfg.base_url, "http://localhost:11434/v1")
        self.assertEqual(default_cfg.model, "qwen3:8b")
        self.assertEqual(default_cfg.api_key, "ollama")
        self.assertTrue(default_cfg.supports_reasoning_effort)

        # 2. Ollama model switching via env vars (qwen3:14b, qwen2.5-coder:7b)
        ollama_14b = providers.resolve_provider_config(
            env={"LLM_PROVIDER": "ollama", "LLM_MODEL": "qwen3:14b"}
        )
        self.assertEqual(ollama_14b.model, "qwen3:14b")
        self.assertEqual(ollama_14b.base_url, "http://localhost:11434/v1")

        # 3. Enterprise providers via env vars (Bedrock, Vertex, Azure, OpenRouter, vLLM)
        bedrock_cfg = providers.resolve_provider_config(
            env={
                "LLM_PROVIDER": "bedrock",
                "LLM_BASE_URL": "https://bedrock-gw.internal.vpc/v1/",
                "LLM_API_KEY": "sk-bedrock-secret-123",
                "LLM_MODEL": "anthropic.claude-3-5-sonnet-20241022-v2:0",
            }
        )
        self.assertEqual(bedrock_cfg.provider, "bedrock")
        self.assertEqual(bedrock_cfg.base_url, "https://bedrock-gw.internal.vpc/v1")
        self.assertFalse(bedrock_cfg.supports_reasoning_effort)
        self.assertNotIn("sk-bedrock-secret-123", repr(bedrock_cfg))
        self.assertEqual(bedrock_cfg.to_safe_dict()["api_key"], "***REDACTED***")

        azure_cfg = providers.resolve_provider_config(
            env={
                "LLM_PROVIDER": "azure_openai",
                "LLM_BASE_URL": "https://bank-corp.openai.azure.com/openai/v1",
                "LLM_API_KEY": "az-secret-999",
                "LLM_MODEL": "gpt-4o",
            }
        )
        self.assertEqual(azure_cfg.provider, "azure")
        self.assertEqual(azure_cfg.extra_headers.get("api-key"), "az-secret-999")
        self.assertEqual(azure_cfg.redacted_headers().get("api-key"), "***REDACTED***")

        vertex_cfg = providers.resolve_provider_config(
            env={
                "LLM_PROVIDER": "gcp-vertex",
                "LLM_BASE_URL": "https://us-central1-aiplatform.googleapis.com/v1beta1/projects/p/locations/us-central1/endpoints/openapi",
                "LLM_API_KEY": "ya29.token",
                "LLM_MODEL": "google/gemini-2.5-pro",
            }
        )
        self.assertEqual(vertex_cfg.provider, "vertex")

        vllm_cfg = providers.resolve_provider_config(env={"LLM_PROVIDER": "vllm"})
        self.assertEqual(vllm_cfg.provider, "vllm")
        self.assertEqual(vllm_cfg.api_key, "EMPTY")

        # 4. Reject missing API keys, missing base URLs, URL userinfo credentials, and invalid timeouts
        with self.assertRaises(ValueError):
            providers.resolve_provider_config(env={"LLM_PROVIDER": "openrouter"})
        with self.assertRaises(ValueError):
            providers.resolve_provider_config(env={"LLM_PROVIDER": "bedrock", "LLM_API_KEY": "k"})
        with self.assertRaises(ValueError):
            providers.resolve_provider_config(
                env={"LLM_PROVIDER": "vllm", "LLM_BASE_URL": "https://user:secret@vllm.internal/v1"}
            )
        with self.assertRaises(ValueError):
            providers.resolve_provider_config(env={"LLM_TIMEOUT": "0"})
        with self.assertRaises(ValueError):
            providers.resolve_provider_config(env={"LLM_TIMEOUT": "99999"})

        # 5. Load config.example.yaml and verify CLI > env > YAML precedence
        self.assertTrue(os.path.isfile(CONFIG_EXAMPLE))
        yaml_cfg = providers.resolve_provider_config(
            config_path=CONFIG_EXAMPLE,
            env={"LLM_PROVIDER": "ollama"},
        )
        self.assertEqual(yaml_cfg.model, "qwen2.5-coder:7b")

        cli_override = providers.resolve_provider_config(
            provider="ollama",
            model="qwen3:14b",
            config_path=CONFIG_EXAMPLE,
            env={"LLM_MODEL": "qwen2.5-coder:7b"},
        )
        self.assertEqual(cli_override.model, "qwen3:14b")

    def test_03_mocked_openai_compatible_http_endpoint_and_error_redaction(self):
        _MockOpenAIHandler.captured_requests = []
        _MockOpenAIHandler.force_error_status = None
        server = HTTPServer(("127.0.0.1", 0), _MockOpenAIHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            secret_token = "enterprise-bearer-token-xyz-987"
            cfg = providers.resolve_provider_config(
                env={
                    "LLM_PROVIDER": "bedrock",
                    "LLM_BASE_URL": f"http://127.0.0.1:{port}/v1",
                    "LLM_API_KEY": secret_token,
                    "LLM_MODEL": "vpc-enterprise-coder-32b",
                    "LLM_TIMEOUT": "15",
                    "LLM_MAX_RETRIES": "0",
                }
            )
            client = providers.create_openai_client(cfg)
            msg = orchestrator.stream_turn(
                client=client,
                model=cfg.model,
                messages=[{"role": "user", "content": "ping"}],
                tools=None,
                temp=0.0,
                reasoning_effort=None,
                secrets=cfg.secret_values(),
            )
            self.assertIn("APPROVED: mock enterprise endpoint OK", msg.content)
            self.assertEqual(len(_MockOpenAIHandler.captured_requests), 1)
            req = _MockOpenAIHandler.captured_requests[0]
            self.assertEqual(req["path"], "/v1/chat/completions")
            self.assertEqual(req["auth"], f"Bearer {secret_token}")
            self.assertEqual(req["model"], "vpc-enterprise-coder-32b")
            self.assertTrue(req["stream"])

            # Verify HTTP error handling scrubs API key from exception message
            _MockOpenAIHandler.force_error_status = 401
            with self.assertRaises(providers.ProviderAPIError) as ctx:
                orchestrator.stream_turn(
                    client=client,
                    model=cfg.model,
                    messages=[{"role": "user", "content": "ping"}],
                    tools=None,
                    temp=0.0,
                    reasoning_effort=None,
                    secrets=cfg.secret_values(),
                )
            self.assertNotIn(secret_token, str(ctx.exception))
            self.assertIn("[REDACTED]", str(ctx.exception))
        finally:
            _MockOpenAIHandler.force_error_status = None
            server.shutdown()
            server.server_close()

    def test_04_audit_logger_sha256_hash_chain_mcp_and_tamper_detection(self):
        with tempfile.TemporaryDirectory() as td:
            log_path = os.path.join(td, "audit.jsonl")
            leaked_key = "ent-live-key-secret-4242"
            logger = audit_logger.AuditLogger(log_path, session_id="sess-test-001", secrets=[leaked_key])

            e1 = logger.log_session_start(
                workspace=td,
                provider="bedrock",
                model="claude-3-5-sonnet",
                base_url="https://bedrock.internal/v1",
                sandbox="docker",
                spec="Fix memory safety issue in buffer.cpp",
            )
            e2 = logger.log_tool_call(
                tool="read_file",
                arguments={"path": "buffer.cpp", "api_key": "SUPER_SECRET_DO_NOT_LOG"},
                output=f"1: int main() {{ /* {leaked_key} */ return 0; }}",
                turn=1,
                elapsed_ms=12.4,
            )
            e3 = logger.log_security_block(
                tool="read_file",
                target=".env.production",
                category="sensitive_file",
                reason="Access denied: '.env.production' is blocked by sensitive file policy",
                turn=1,
            )
            e4 = logger.log_compile_and_test(
                output="EXIT_CODE: 0\nSTDOUT:\nALL TESTS PASSED\nSTDERR:\n",
                critic_approved=True,
                critic_verdict="APPROVED: Verified bounds check and tests.",
                turn=2,
            )
            sample_diff = "diff --git a/buffer.cpp b/buffer.cpp\n@@ -1 +1 @@\n-old\n+new\n"
            e5 = logger.log_git_diff(diff_text=sample_diff, changed_files=["buffer.cpp"], status="approved")
            e6 = logger.log_session_end(
                status="approved",
                turns=2,
                security_blocks=1,
                critic_rejections=0,
                git_diff=sample_diff,
            )

            # Verify hash-chain linkage & secret redaction (keys + inline secret values)
            self.assertEqual(e1["prev_hash"], audit_logger.GENESIS_HASH)
            self.assertEqual(e2["prev_hash"], e1["entry_hash"])
            self.assertEqual(e3["prev_hash"], e2["entry_hash"])
            self.assertEqual(e4["prev_hash"], e3["entry_hash"])
            self.assertEqual(e5["prev_hash"], e4["entry_hash"])
            self.assertEqual(e6["prev_hash"], e5["entry_hash"])
            self.assertEqual(e2["payload"]["arguments"]["api_key"], "[REDACTED]")
            self.assertNotIn(leaked_key, e2["payload"]["output_preview"])
            self.assertIn("[REDACTED]", e2["payload"]["output_preview"])
            self.assertEqual(e5["payload"]["git_diff_sha256"], audit_logger.sha256_text(sample_diff))
            self.assertEqual(e6["payload"]["git_diff_sha256"], audit_logger.sha256_text(sample_diff))

            # Verify standalone mcp_server.py --audit-log emits full chained session events
            mcp_ws = os.path.join(td, "mcp_ws")
            os.makedirs(mcp_ws, exist_ok=True)
            subprocess.run(
                "git init -q && git config user.email 't@local' && git config user.name 'T' && git commit --allow-empty -m 'init' -q",
                shell=True,
                cwd=mcp_ws,
                check=True,
            )
            mcp_audit = os.path.join(td, "mcp_audit.jsonl")
            mcp = orchestrator.MCPClient(MCP_SERVER_SCRIPT, workspace=mcp_ws, audit_log=mcp_audit)
            try:
                mcp.call_tool("write_file", {"path": "main.c", "content": "int main(void) { return 0; }\n"})
                mcp.call_tool("compile_and_test", {})
                with self.assertRaises(RuntimeError):
                    mcp.call_tool("read_file", {"path": "../../etc/passwd"})
                mcp.call_tool("git_diff", {})
            finally:
                mcp.close()

            ok_mcp, errs_mcp, count_mcp = audit_logger.verify_audit_log(mcp_audit)
            self.assertTrue(ok_mcp, errs_mcp)
            self.assertGreaterEqual(count_mcp, 7)
            with open(mcp_audit, "r", encoding="utf-8") as f:
                mcp_events = [json.loads(line)["event_type"] for line in f if line.strip()]
            for expected_ev in ("session_start", "tool_call", "compile_and_test", "security_block", "git_diff", "session_end"):
                self.assertIn(expected_ev, mcp_events)

            # Verify clean multi-session append + CLI --verify on log_path
            logger2 = audit_logger.AuditLogger(log_path, session_id="sess-test-002")
            e7 = logger2.log_session_start(
                workspace=td,
                provider="ollama",
                model="qwen2.5-coder:7b",
                base_url="http://localhost:11434/v1",
                sandbox="host",
                spec="Follow-up check",
            )
            self.assertEqual(e7["seq"], 7)
            self.assertEqual(e7["prev_hash"], e6["entry_hash"])

            cli_ok = subprocess.run(
                [sys.executable, AUDIT_LOGGER_SCRIPT, "--verify", log_path],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(cli_ok.returncode, 0, cli_ok.stderr)
            self.assertIn("Verified 7 hash-chained audit entries", cli_ok.stdout)

            with open(log_path, "r", encoding="utf-8") as f:
                orig_lines = f.read().splitlines()

            # Tamper Case A: Alter a payload field in line 3
            tampered_payload_path = os.path.join(td, "tampered_payload.jsonl")
            mutated = list(orig_lines)
            row3 = json.loads(mutated[2])
            row3["payload"]["reason"] = "Allowed by admin"
            mutated[2] = json.dumps(row3, sort_keys=True, separators=(",", ":"))
            with open(tampered_payload_path, "w", encoding="utf-8") as f:
                f.write("\n".join(mutated) + "\n")
            ok_a, errs_a, _ = audit_logger.verify_audit_log(tampered_payload_path)
            self.assertFalse(ok_a)
            self.assertTrue(any("entry_hash tampering detected" in e for e in errs_a), errs_a)

            # Tamper Case B: Delete a security_block entry (line 3)
            deleted_line_path = os.path.join(td, "deleted_line.jsonl")
            with open(deleted_line_path, "w", encoding="utf-8") as f:
                f.write("\n".join(orig_lines[:2] + orig_lines[3:]) + "\n")
            ok_b, errs_b, _ = audit_logger.verify_audit_log(deleted_line_path)
            self.assertFalse(ok_b)
            self.assertTrue(any("prev_hash chain break" in e for e in errs_b), errs_b)

            # Tamper Case C: Reorder two entries
            reordered_path = os.path.join(td, "reordered.jsonl")
            reordered = list(orig_lines)
            reordered[1], reordered[2] = reordered[2], reordered[1]
            with open(reordered_path, "w", encoding="utf-8") as f:
                f.write("\n".join(reordered) + "\n")
            ok_c, errs_c, _ = audit_logger.verify_audit_log(reordered_path)
            self.assertFalse(ok_c)
            self.assertTrue(any("sequence mismatch" in e for e in errs_c), errs_c)

            cli_fail = subprocess.run(
                [sys.executable, AUDIT_LOGGER_SCRIPT, "--verify", tampered_payload_path],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(cli_fail.returncode, 0)

    def test_05_deploy_bundle_docker_hardening_flags(self):
        dockerfile_path = os.path.join(DEPLOY_DIR, "Dockerfile")
        compose_path = os.path.join(DEPLOY_DIR, "docker-compose.yml")
        vpc_compose_path = os.path.join(DEPLOY_DIR, "docker-compose.vpc.yml")
        quickstart_path = os.path.join(DEPLOY_DIR, "QUICKSTART.md")

        for path in (dockerfile_path, compose_path, vpc_compose_path, quickstart_path):
            self.assertTrue(os.path.isfile(path), f"Missing deployment artifact: {path}")

        with open(dockerfile_path, "r", encoding="utf-8") as f:
            dockerfile = f.read()
        self.assertIn("USER 10001:10001", dockerfile)
        self.assertIn("useradd", dockerfile)
        self.assertIn("/usr/sbin/nologin", dockerfile)
        self.assertIn("HEALTHCHECK", dockerfile)

        with open(compose_path, "r", encoding="utf-8") as f:
            compose = yaml.safe_load(f)

        svc = compose["services"]["agent-sandbox"]
        self.assertEqual(str(svc.get("user")), "10001:10001")
        self.assertTrue(svc.get("read_only"))
        self.assertEqual(svc.get("network_mode"), "none")
        self.assertIn("no-new-privileges:true", svc.get("security_opt", []))
        self.assertIn("ALL", svc.get("cap_drop", []))
        self.assertTrue(any(str(t).startswith("/tmp:") for t in svc.get("tmpfs", [])))
        self.assertGreater(int(svc.get("pids_limit", 0)), 0)
        self.assertTrue(bool(svc.get("mem_limit")))
        self.assertTrue(bool(svc.get("cpus")))
        limits = svc.get("deploy", {}).get("resources", {}).get("limits", {})
        self.assertIn("cpus", limits)
        self.assertIn("memory", limits)

        workspace_vols = [
            v for v in svc.get("volumes", [])
            if isinstance(v, dict) and v.get("target") == "/workspace"
        ]
        self.assertEqual(len(workspace_vols), 1)
        self.assertTrue(workspace_vols[0].get("read_only"))

        with open(vpc_compose_path, "r", encoding="utf-8") as f:
            vpc_compose = yaml.safe_load(f)
        self.assertTrue(vpc_compose["networks"]["agent_internal"].get("internal"))

        with open(quickstart_path, "r", encoding="utf-8") as f:
            quickstart = f.read()
        for marker in ("LLM_PROVIDER", "LLM_BASE_URL", "LLM_API_KEY", "LLM_MODEL", "audit_logger.py --verify", "network_mode: none"):
            self.assertIn(marker, quickstart)

    def test_06_demo_showcase_end_to_end(self):
        result = demo_showcase.run_demo(pace=0.0, use_color=False, live_llm=False)
        self.assertTrue(result["act1_baseline_failed"])
        self.assertTrue(result["act1_approved"])
        self.assertEqual(result["act2_blocked_count"], 4)
        self.assertTrue(result["act3_chain_verified"])
        self.assertTrue(result["act3_tamper_detected"])
        self.assertLess(result["elapsed_sec"], 30.0)


if __name__ == "__main__":
    unittest.main()
