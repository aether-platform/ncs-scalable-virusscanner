"""Minimal webhook receiver that stores POSTed payloads and serves them via GET /logs."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

_logs: list[str] = []
_lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        with _lock:
            _logs.append(body)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def do_GET(self):
        with _lock:
            payload = json.dumps(_logs)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(payload.encode())

    def log_message(self, fmt, *args):
        print(f"[mock-console] {fmt % args}")


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 80), Handler)
    print("[mock-console] Listening on :80")
    server.serve_forever()
