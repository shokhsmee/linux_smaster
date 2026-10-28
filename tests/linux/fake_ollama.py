"""Minimal stand-in for an unauthenticated Ollama API, bound to 0.0.0.0:11434."""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/api/tags":
            body = json.dumps({"models": []}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("fake-ollama: " + fmt % args + "\n")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 11434
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()
