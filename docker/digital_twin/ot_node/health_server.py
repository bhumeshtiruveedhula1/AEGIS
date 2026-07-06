"""OT Node health server — same pattern, port 9003."""

from __future__ import annotations
import json, sys, threading, os
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

HEALTH_FILE = Path("/tmp/generator_health.json")
HEALTH_PORT = int(os.environ.get("DT_HEALTH_PORT", "9003"))

class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/health":
            self.send_response(404); self.end_headers(); return
        try:
            data = HEALTH_FILE.read_text(encoding="utf-8")
            body = data.encode("utf-8")
            status_code = 200 if json.loads(data).get("status") == "running" else 503
        except Exception:  # noqa: BLE001
            body = b'{"status":"starting"}'; status_code = 503
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def log_message(self, *args: object) -> None: pass

def start_health_server() -> None:
    server = HTTPServer(("0.0.0.0", HEALTH_PORT), HealthHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(json.dumps({"msg": "health_server_started", "port": HEALTH_PORT}), file=sys.stderr, flush=True)
