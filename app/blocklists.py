from __future__ import annotations

import hashlib
import io
import ipaddress
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Iterable

MAX_BYTES = int(os.getenv("MAX_BLOCKLIST_BYTES", str(100 * 1024 * 1024)))
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)


@dataclass(slots=True)
class ParseResult:
    domains: set[str]
    ignored: int = 0


@dataclass(frozen=True, slots=True)
class FetchResult:
    text: str | None
    etag: str | None = None
    last_modified: str | None = None
    content_hash: str | None = None
    not_modified: bool = False


def normalize_domain(value: str) -> str | None:
    value = value.strip().lower().rstrip(".")
    if value.startswith("*."):
        value = value[2:]
    if not value or value == "localhost":
        return None
    if not value.isascii():
        try:
            value = value.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    if not DOMAIN_RE.match(value):
        return None
    # A bare TLD is almost always a malformed list entry and is dangerous to block.
    if "." not in value:
        return None
    return value


def _from_adblock(line: str, allow_exceptions: bool = False) -> str | None:
    if line.startswith("@@"):
        if not allow_exceptions:
            return None
        line = line[2:]
    if line.startswith("||"):
        candidate = line[2:]
        candidate = candidate.split("^", 1)[0]
        candidate = candidate.split("$", 1)[0]
        candidate = candidate.lstrip(".")
        return normalize_domain(candidate)
    return None


def parse_blocklist(
    text: str,
    list_format: str = "auto",
    list_type: str = "block",
) -> ParseResult:
    domains: set[str] = set()
    ignored = 0
    for raw in io.StringIO(text):
        line = raw.strip()
        if not line or line.startswith(("#", "!", ";", "[")):
            continue

        candidate: str | None = None
        if list_format in ("auto", "adblock") and line.startswith(("||", "@@||")):
            candidate = _from_adblock(
                line,
                allow_exceptions=list_type == "whitelist",
            )
        elif list_format in ("auto", "hosts"):
            # Hosts-form lines: 0.0.0.0 example.com [aliases...]
            no_comment = line.split("#", 1)[0].strip()
            parts = no_comment.split()
            if len(parts) >= 2:
                try:
                    ipaddress.ip_address(parts[0])
                    for p in parts[1:]:
                        d = normalize_domain(p)
                        if d:
                            domains.add(d)
                    continue
                except ValueError:
                    pass
            if list_format == "hosts":
                candidate = None
            else:
                candidate = normalize_domain(parts[0]) if parts else None
        else:
            candidate = normalize_domain(line.split()[0])

        if candidate:
            domains.add(candidate)
        else:
            ignored += 1
    return ParseResult(domains=domains, ignored=ignored)


def fetch_url_conditional(
    url: str,
    etag: str | None = None,
    last_modified: str | None = None,
) -> FetchResult:
    headers = {"User-Agent": "Technitium-Remote-Policy-Blocker/1.0"}
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified

    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            length = resp.headers.get("Content-Length")
            if length and int(length) > MAX_BYTES:
                raise ValueError(
                    f"block list exceeds MAX_BLOCKLIST_BYTES ({MAX_BYTES})"
                )
            data = resp.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise ValueError(
                    f"block list exceeds MAX_BLOCKLIST_BYTES ({MAX_BYTES})"
                )
            return FetchResult(
                text=data.decode("utf-8", errors="replace"),
                etag=resp.headers.get("ETag"),
                last_modified=resp.headers.get("Last-Modified"),
                content_hash=hashlib.sha256(data).hexdigest(),
            )
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return FetchResult(
                text=None,
                etag=exc.headers.get("ETag") or etag,
                last_modified=exc.headers.get("Last-Modified") or last_modified,
                not_modified=True,
            )
        raise


def fetch_url(url: str) -> str:
    result = fetch_url_conditional(url)
    return result.text or ""
