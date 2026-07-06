"""
Minimal HTTP health server for Digital Twin containers.
Reads generator_health.json and exposes /health endpoint.

This runs in a background thread alongside the generator process.
It reads the health.json file written by BaseGenerator._write_health().
"""

from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


HEALTH_FILE = Path("/tmp/generator_health.json")
HEALTH_PORT = int(__import__("os").environ.get("DT_HEALTH_PORT", "9000"))


class HealthHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler — serves /health from generator_health.json."""

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/health":
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'{"error":"not found"}')
            return

        try:
            data = HEALTH_FILE.read_text(encoding="utf-8")
            body = data.encode("utf-8")
            payload = json.loads(data)
            status_code = 200 if payload.get("status") == "running" else 503
        except Exception:  # noqa: BLE001
            body = b'{"status":"starting","message":"health file not yet available"}'
            status_code = 503

        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass  # Suppress default HTTP access logs


def start_health_server() -> None:
    """Start the health server in a daemon thread."""
    server = HTTPServer(("0.0.0.0", HEALTH_PORT), HealthHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(
        json.dumps({"msg": "health_server_started", "port": HEALTH_PORT}),
        file=sys.stderr,
        flush=True,
    )
