#!/usr/bin/env python3
"""Fake OpenSecOps origin with programmable faults.

The real origin is another team's and flaps (4/60 good). Waiting on it is not
a measurable loop. This reproduces every failure mode locally so the pipeline's
REACTION can be tested deterministically.

MODE env:
  healthy   - everything 200/401
  dead_api  - / 200, /health+/api 502   (what production actually does today)
  flapping  - /api good ~7% of the time (measured ratio)
  no_route  - connection refused (overlay problem)
  api_500   - upload answers 500 (the importer bug)
"""
import http.server, os, random, sys

MODE = os.environ.get("MODE", "healthy")

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, body=b"", ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        p = self.path
        if MODE == "dead_api":
            if p == "/": return self._send(200, b"<html>spa</html>", "text/html")
            return self._send(502, b"<html>502</html>", "text/html")
        if MODE == "flapping" and p.startswith("/api"):
            if random.random() > 0.07: return self._send(502, b"<html>502</html>", "text/html")
        if p == "/health": return self._send(200, b'{"status":"ok","version":"1.0.0"}')
        if p == "/": return self._send(200, b"<html>spa</html>", "text/html")
        if p.startswith("/api/imports/parsers"):
            if self.headers.get("Authorization"): return self._send(200, b'["semgrep","trivy"]')
            return self._send(401, b'{"detail":"unauthenticated"}')
        return self._send(404, b'{"detail":"not found"}')
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        self.rfile.read(n)
        if MODE == "api_500": return self._send(500, b'{"detail":"Server Error"}')
        return self._send(201, b'{"import_id":1,"findings_count":3}')

http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
