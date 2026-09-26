"""Bounded administration workers and streaming request size enforcement."""
from __future__ import annotations

import asyncio
import inspect
import secrets
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from functools import wraps

from fastapi import HTTPException
from starlette.responses import JSONResponse

_workers = ThreadPoolExecutor(max_workers=4, thread_name_prefix="admin")
_slots = threading.BoundedSemaphore(12)


async def run_admin(function, *args, **kwargs):
    if not _slots.acquire(blocking=False):
        raise HTTPException(503, "Administration is busy; retry shortly", headers={"Retry-After": "2"})
    try:
        future = _workers.submit(function, *args, **kwargs)
    except BaseException:
        _slots.release()
        raise
    future.add_done_callback(lambda _: _slots.release())
    return await asyncio.wrap_future(future)


def blocking_action(function):
    @wraps(function)
    async def wrapped(*args, **kwargs):
        return await run_admin(function, *args, **kwargs)
    wrapped.__signature__ = inspect.signature(function, eval_str=True)
    return wrapped


def admin_action(require_session):
    def decorate(function):
        @wraps(function)
        async def wrapped(*args, **kwargs):
            request = kwargs["request"]
            session = await run_admin(require_session, request)
            async with request.form(max_files=4, max_fields=128) as form:
                token = str(form.get("csrf_token", ""))
                if not token or not secrets.compare_digest(token, session.csrf_token):
                    raise HTTPException(403, "invalid CSRF token")
                request.state.admin_session = session
                request.state.admin_form = form
                # Keep upload handles alive if the caller disconnects mid-write.
                task = asyncio.create_task(run_admin(function, *args, **kwargs))
                try:
                    return await asyncio.shield(task)
                except asyncio.CancelledError:
                    await task
                    raise
        wrapped.__signature__ = inspect.signature(function, eval_str=True)
        return wrapped
    return decorate


class LoginLimiter:
    """Per-peer and global limits; do not trust user-controlled forwarding headers."""
    def __init__(self):
        self.lock = threading.Lock()
        self.peers = OrderedDict()
        self.global_attempts = []

    def check(self, peer):
        now = time.monotonic()
        with self.lock:
            self.global_attempts = [t for t in self.global_attempts if t > now - 60]
            attempts = [t for t in self.peers.pop(peer, []) if t > now - 60]
            self.peers[peer] = attempts
            if len(self.peers) > 4096:
                self.peers.popitem(last=False)
            if len(attempts) >= 10 or len(self.global_attempts) >= 100:
                raise HTTPException(429, "Too many sign-in attempts", headers={"Retry-After": "60"})
            attempts.append(now)
            self.global_attempts.append(now)


login_limiter = LoginLimiter()


class BodyLimitMiddleware:
    def __init__(self, app, upload_limit):
        self.app = app
        self.upload_limit = upload_limit

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)
        path = scope.get("path", "")
        limit = 256 * 1024
        if path.startswith("/admin/lists"):
            limit = self.upload_limit + 1024 * 1024
        elif path == "/admin/settings/tls":
            limit = 4 * 1024 * 1024
        headers = dict(scope.get("headers", []))
        try:
            length = int(headers.get(b"content-length", b"0"))
        except ValueError:
            return await JSONResponse({"detail": "Invalid Content-Length"}, status_code=400)(scope, receive, send)
        if length > limit:
            return await JSONResponse({"detail": "Request body too large"}, status_code=413)(scope, receive, send)
        total = 0

        async def bounded_receive():
            nonlocal total
            message = await receive()
            total += len(message.get("body", b""))
            if total > limit:
                raise HTTPException(413, "Request body too large")
            return message

        await self.app(scope, bounded_receive, send)
