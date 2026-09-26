"""HTTP-only list fetching, with IP validation at the socket connection boundary."""
from __future__ import annotations

import http.client
import ipaddress
import os
import socket
import urllib.request
from urllib.parse import urlsplit


def validate_source_url(url):
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise ValueError("Invalid source URL") from exc
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        raise ValueError("List sources must use HTTP or HTTPS")
    if parts.username is not None or parts.password is not None or parts.fragment:
        raise ValueError("Source URLs must not contain credentials or fragments")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Invalid source port")
    return parts


def _allowed(host, address):
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    if ip.is_global and not ip.is_multicast and not ip.is_unspecified:
        return True
    for entry in os.getenv("BLOCKLIST_PRIVATE_HOSTS", "").split(","):
        entry = entry.strip().lower().rstrip(".")
        if not entry:
            continue
        try:
            if ip in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            if host.lower().rstrip(".") == entry:
                return True
    return False


def _connect(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):
    host, port = address
    candidates = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not candidates or any(not _allowed(host, item[4][0]) for item in candidates):
        raise ValueError("Private list destination requires BLOCKLIST_PRIVATE_HOSTS allowlisting")
    last_error = None
    for family, kind, protocol, _, sockaddr in candidates:
        sock = socket.socket(family, kind, protocol)
        try:
            if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                sock.settimeout(timeout)
            if source_address:
                sock.bind(source_address)
            # Use the validated numeric sockaddr; never resolve the host again.
            sock.connect(sockaddr)
            return sock
        except OSError as exc:
            last_error = exc
            sock.close()
    raise last_error or OSError("No destination addresses")


class _HTTPConnection(http.client.HTTPConnection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = _connect


class _HTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = _connect


class _HTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_HTTPConnection, req)


class _HTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_HTTPSConnection, req, context=self._context)


class _RedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_source_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def open_source(request, timeout=30):
    validate_source_url(request.full_url)
    # Explicitly ignore environment proxies: they bypass destination validation.
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _HTTPHandler(), _HTTPSHandler(), _RedirectHandler()
    )
    return opener.open(request, timeout=timeout)
