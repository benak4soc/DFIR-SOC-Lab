"""Webhook Shuffle calls with a Wazuh alert JSON body."""

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from dfir_soc.clients import IrisClient, MispClient
from dfir_soc.playbook import handle_alert


def build_clients():
    iris_url = os.environ.get("IRIS_URL", "").strip()
    misp_url = os.environ.get("MISP_URL", "").strip()
    iris = None
    misp = None
    if iris_url and os.environ.get("IRIS_API_KEY"):
        iris = IrisClient(
            iris_url,
            os.environ["IRIS_API_KEY"],
            customer_id=int(os.environ.get("IRIS_CUSTOMER_ID", "1")),
            classification_id=int(os.environ.get("IRIS_CLASSIFICATION_ID", "1")),
            severity_id=int(os.environ.get("IRIS_SEVERITY_ID", "4")),
        )
    if misp_url and os.environ.get("MISP_API_KEY"):
        misp = MispClient(misp_url, os.environ["MISP_API_KEY"])
    return iris, misp


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/health":
            self._json(404, {"status": "not-found"})
            return
        self._json(200, {"status": "ok"})

    def do_POST(self):
        if self.path != "/v1/playbook":
            self._json(404, {"status": "not-found"})
            return
        expected = os.environ.get("LAB_TOKEN", "")
        if expected and self.headers.get("X-Lab-Token") != expected:
            self._json(401, {"status": "unauthorized"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            alert = json.loads(raw.decode())
        except json.JSONDecodeError:
            self._json(400, {"status": "invalid-json"})
            return
        iris, misp = build_clients()
        try:
            plan = handle_alert(alert, iris, misp)
        except RuntimeError as exc:
            self._json(502, {"status": "upstream-error", "detail": str(exc)})
            return
        self._json(200, plan)

    def log_message(self, fmt, *args):
        return

    def _json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    host = os.environ.get("PLAYBOOK_HOST", "0.0.0.0")
    port = int(os.environ.get("PLAYBOOK_PORT", "8088"))
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"Playbook webhook listening on {host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
