"""Deterministic local lab target for end-to-end tests and demos.

The lab is deliberately small and intentionally vulnerable in the exact ways
covered by the reviewed discovery profiles. It never touches a real network
service and is safe to run on loopback. It exists so the full pipeline can be
exercised without a live bug-bounty target or Docker.

Findings produced against the lab are still subject to every gate: scope,
evidence, reproducibility, oracle, severity, deduplication, and human review.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar
from urllib.parse import parse_qs, urlsplit

LAB_CANARY_HEADER = "X-Huntress-Lab"
LAB_SQL_ERROR = (
    "You have an error in your SQL syntax; check the manual that corresponds to "
    "your MySQL server version for the right syntax to use near ''' at line 1"
)
LAB_ENV = """# Synthetic lab configuration. Not a real secret.
APP_ENV=lab
SECRET_KEY=huntress-lab-not-a-real-secret
DATABASE_URL=sqlite:///./lab.db
API_TOKEN=lab-token-for-tests-only
"""
LAB_GIT_HEAD = "ref: refs/heads/main\n"
LAB_UPLOADS = """<!doctype html>
<html><head><title>Index of /uploads/</title></head>
<body><h1>Index of /uploads/</h1>
<a href="../">Parent Directory</a>
<a href="notes.txt">notes.txt</a>
</body></html>
"""
LAB_REDIRECT_PARAMETERS = ("next", "url", "redirect", "return", "continue")
LAB_REFLECTION_PARAMETERS = ("q", "search")


@dataclass(frozen=True, slots=True)
class LabServer:
    """A running lab server plus the information needed to stop it."""

    server: ThreadingHTTPServer
    thread: threading.Thread

    @property
    def host(self) -> str:
        return str(self.server.server_address[0])

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5.0)


class _LabHandler(BaseHTTPRequestHandler):
    server_version = "HuntressLab/1.0"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    _quiet: ClassVar[bool] = True

    def log_message(self, format: str, *args: object) -> None:
        if not self._quiet:
            super().log_message(format, *args)

    def _send(self, status: int, body: str, headers: dict[str, str] | None = None) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        merged = {"Content-Type": "text/html; charset=utf-8", LAB_CANARY_HEADER: "1"}
        if headers:
            merged.update(headers)
        for name, value in merged.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _send_json(self, status: int, value: object) -> None:
        self._send(
            status,
            json.dumps(value, sort_keys=True),
            {"Content-Type": "application/json"},
        )

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_OPTIONS(self) -> None:
        origin = self.headers.get("Origin")
        headers: dict[str, str] = {"Allow": "GET, HEAD, OPTIONS"}
        if origin:
            headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Allow-Credentials"] = "true"
        self._send(204, "", headers)

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        path = parsed.path or "/"
        query = parse_qs(parsed.query, keep_blank_values=True)

        if path in {"/health", "/healthz"}:
            self._send_json(200, {"status": "ok", "service": "huntress-lab"})
            return
        if path == "/.env":
            self._send(200, LAB_ENV, {"Content-Type": "text/plain; charset=utf-8"})
            return
        if path == "/.git/HEAD":
            self._send(200, LAB_GIT_HEAD, {"Content-Type": "text/plain; charset=utf-8"})
            return
        if path in {"/uploads", "/uploads/"}:
            self._send(200, LAB_UPLOADS)
            return
        if path == "/backup.zip":
            # Deliberately absent: the profile should not report a hit.
            self._send(404, "not found", {"Content-Type": "text/plain"})
            return

        for parameter in LAB_REDIRECT_PARAMETERS:
            values = query.get(parameter)
            if values:
                self._send(302, "", {"Location": values[0]})
                return

        q_values = query.get("q")
        if q_values and q_values[0] == "'":
            self._send(
                500,
                f"<html><body><h1>Database error</h1><pre>{LAB_SQL_ERROR}</pre></body></html>",
                {"Content-Type": "text/html; charset=utf-8"},
            )
            return

        reflected = ""
        for parameter in LAB_REFLECTION_PARAMETERS:
            values = query.get(parameter)
            if values:
                # Intentionally unescaped: this is the lab's reflected-XSS signal.
                reflected = values[0]
                break

        origin = self.headers.get("Origin")
        headers: dict[str, str] = {}
        if origin:
            # Intentionally unsafe CORS: reflect any origin with credentials.
            headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Allow-Credentials"] = "true"

        body = f"""<!doctype html>
<html><head><title>Huntress Lab</title></head>
<body>
<h1>Huntress Lab</h1>
<p>Deterministic local target for the reviewed Huntress profiles.</p>
<div id="reflection">{reflected}</div>
</body></html>
"""
        self._send(200, body, headers)


def create_lab_server(host: str = "127.0.0.1", port: int = 0) -> LabServer:
    """Bind a lab server without starting it.

    The returned object owns a daemon thread. Call ``start_lab_server`` for a
    bound-and-serving instance, or use ``server.server`` directly.
    """

    server = ThreadingHTTPServer((host, port), _LabHandler)
    server.daemon_threads = True
    thread = threading.Thread(
        target=server.serve_forever,
        name="huntress-lab",
        daemon=True,
    )
    return LabServer(server=server, thread=thread)


def start_lab_server(host: str = "127.0.0.1", port: int = 0) -> LabServer:
    """Create and start a lab server in a background daemon thread."""

    lab = create_lab_server(host=host, port=port)
    lab.thread.start()
    return lab


def serve_lab(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Run the lab server in the foreground until interrupted."""

    server = ThreadingHTTPServer((host, port), _LabHandler)
    server.daemon_threads = True
    try:
        print(f"Huntress lab listening on http://{host}:{server.server_address[1]}")
        server.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover - interactive convenience
        pass
    finally:
        server.server_close()


__all__ = [
    "LAB_ENV",
    "LAB_GIT_HEAD",
    "LAB_SQL_ERROR",
    "LabServer",
    "create_lab_server",
    "serve_lab",
    "start_lab_server",
]
