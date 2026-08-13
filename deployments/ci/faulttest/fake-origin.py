#!/usr/bin/env python3
"""Fake OpenSecOps origin with programmable faults.

The real origin is another team's and flaps (4/60 good). Waiting on it is not
a measurable loop. This reproduces every failure mode locally so the pipeline's
REACTION can be tested deterministically.

MODE env:
  healthy   - everything 200/401
  dead_api  - / 200, /health+/api 502   (what production actually does today)
  flapping  - /api good on exactly every 20th request (deterministic)
  flapstat  - /api good ~7% of the time at random (the measured ratio)
  no_route  - connection refused (overlay problem)
  api_500   - upload answers 500 (the importer bug)

WHY TWO FLAPPING MODES. The honest model of production is random: 4 of 60.
But a random model makes the MATRIX ITSELF fail ~5% of the time (0.93^40),
and a gate that cries wolf one run in twenty gets ignored, which is worse
than no gate. So the gate uses a deterministic stand-in with the same
REQUIREMENT -- one success only after many failures -- and the random model
is kept as a separate, explicitly statistical check.

The number 20 is not decorative: it is above 12 and below 40, so it still
fails the old 12-retry loop (the defect this test caught) and passes the
current 40, without depending on a coin toss.
"""
import http.server, os, random, sys

MODE = os.environ.get("MODE", "healthy")
# Deterministic flap: succeed once every FLAP_EVERY-th /api request.
FLAP_EVERY = int(os.environ.get("FLAP_EVERY", "20"))
_api_hits = 0

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
        if MODE in ("flapping", "flapstat") and p.startswith("/api"):
            global _api_hits
            _api_hits += 1
            bad = (_api_hits % FLAP_EVERY != 0) if MODE == "flapping" \
                else (random.random() > 0.07)
            if bad: return self._send(502, b"<html>502</html>", "text/html")
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
