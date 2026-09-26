"""Unprivileged client for the separately installed host updater."""
import http.client
import json
import os
import secrets
import socket
from pathlib import Path

from starlette.responses import JSONResponse

RUNTIME = Path(os.getenv("UPDATER_RUNTIME_DIR", "/run/blockinator-update"))


class LocalConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(str(RUNTIME / "updater.sock"))


def updater_request(action="status", values=None):
    connection = LocalConnection("localhost", timeout=3)
    try:
        connection.request("POST", "/" + action, json.dumps(values or {}), {"Content-Type": "application/json"})
        response = connection.getresponse()
        data = json.loads(response.read(128 * 1024))
        if response.status != 200:
            raise ValueError(data.get("error", "Updater rejected the request"))
        return data
    except (OSError, http.client.HTTPException) as exc:
        raise ValueError("Host updater unavailable. Install and start the update service on the Docker host.") from exc
    finally:
        connection.close()


def probe_authorized(scope):
    token_file = RUNTIME / "probe-token"
    try:
        token = token_file.read_bytes().strip()
    except OSError:
        return False
    provided = dict(scope.get("headers", [])).get(b"x-blockinator-probe", b"")
    return bool(token) and secrets.compare_digest(provided, token)


class UpdateMaintenanceMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http" and (RUNTIME / "maintenance").exists():
            if scope.get("path") not in {"/healthz", "/readyz"} and not probe_authorized(scope):
                response = JSONResponse({"detail": "Blockinator is updating; retry shortly"}, status_code=503,
                                        headers={"Retry-After": "30", "Cache-Control": "no-store"})
                return await response(scope, receive, send)
        await self.app(scope, receive, send)
