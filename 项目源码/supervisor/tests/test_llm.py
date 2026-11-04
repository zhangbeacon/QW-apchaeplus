import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace

from variant_supervisor.llm import diagnose_with_llm
from variant_supervisor.watchdog import RunResult


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        body = json.dumps(
            {
                "choices": [
                    {
                        "message": {
                            "content": '{"cause":"PORT_CONFLICT","action":"clean",'
                            '"confidence":0.9,"rationale":"stale listener"}'
                        }
                    }
                ]
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class LLMTest(unittest.TestCase):
    def test_json_response_is_parsed(self):
        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as d:
                log = Path(d) / "build.log"
                log.write_text("Address already in use\n", encoding="utf-8")
                cfg = SimpleNamespace(
                    llm_enabled=True,
                    llm_api_key_env="TEST_KEY",
                    llm_model="test-model",
                    llm_base=f"http://127.0.0.1:{server.server_port}/v1",
                )
                os.environ["TEST_KEY"] = "x"
                result = RunResult(1, False, False, False, 0.1, 5.0, log)
                payload, error = diagnose_with_llm(cfg, "build", ["echo"], result, log)
                self.assertIsNone(error)
                self.assertEqual(payload["action"], "clean")
        finally:
            server.shutdown()
            server.server_close()
            os.environ.pop("TEST_KEY", None)

    def test_missing_key_returns_error(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "build.log"
            log.write_text("x", encoding="utf-8")
            cfg = SimpleNamespace(
                llm_enabled=True,
                llm_api_key_env="TEST_KEY_MISSING",
                llm_model="m",
                llm_base="http://127.0.0.1:1/v1",
            )
            os.environ.pop("TEST_KEY_MISSING", None)
            result = RunResult(1, False, False, False, 0.1, 5.0, log)
            payload, error = diagnose_with_llm(cfg, "build", ["echo"], result, log)
            self.assertIsNone(payload)
            self.assertIn("missing env", error)


if __name__ == "__main__":
    unittest.main()

