from __future__ import annotations

import ipaddress
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass

import dns.exception
import dns.resolver
import dns.reversename


@dataclass(frozen=True, slots=True)
class ReverseDnsResult:
    status: str
    hostname: str | None = None
    error: str | None = None


class ReverseDnsResolver:
    """Small, bounded PTR resolver for UI display.

    DNS decisions never call this class. Reverse lookups are performed only while
    rendering administrative pages and are cached to avoid repeatedly querying
    DNS for the same client.
    """

    def __init__(self) -> None:
        self.lookup_timeout = max(0.1, float(os.getenv("RDNS_TIMEOUT_SECONDS", "0.5")))
        self.page_budget = max(self.lookup_timeout, float(os.getenv("RDNS_PAGE_BUDGET_SECONDS", "1.25")))
        self.positive_ttl = max(30, int(os.getenv("RDNS_CACHE_TTL_SECONDS", "300")))
        self.negative_ttl = max(15, int(os.getenv("RDNS_NEGATIVE_TTL_SECONDS", "60")))
        self.max_workers = max(2, min(int(os.getenv("RDNS_WORKERS", "12")), 32))
        self.nameservers = [
            value.strip()
            for value in os.getenv("RDNS_NAMESERVERS", "").split(",")
            if value.strip()
        ]
        self._cache: dict[str, tuple[float, str | None]] = {}
        self._lock = threading.RLock()
        self._thread_local = threading.local()
        self._executor = ThreadPoolExecutor(
            max_workers=self.max_workers,
            thread_name_prefix="blockinator-rdns",
        )

    def _cache_get(self, address: str) -> tuple[bool, str | None]:
        now = time.monotonic()
        with self._lock:
            cached = self._cache.get(address)
            if cached is None:
                return False, None
            expires_at, hostname = cached
            if expires_at <= now:
                self._cache.pop(address, None)
                return False, None
            return True, hostname

    def _cache_put(self, address: str, hostname: str | None) -> None:
        ttl = self.positive_ttl if hostname else self.negative_ttl
        with self._lock:
            self._cache[address] = (time.monotonic() + ttl, hostname)
            # Keep a long-running admin process from growing this cache forever.
            if len(self._cache) > 4096:
                now = time.monotonic()
                expired = [key for key, (expiry, _) in self._cache.items() if expiry <= now]
                for key in expired[:2048]:
                    self._cache.pop(key, None)
                if len(self._cache) > 4096:
                    for key in list(self._cache)[:1024]:
                        self._cache.pop(key, None)

    def _resolver(self) -> dns.resolver.Resolver:
        # Resolver construction can parse system resolver configuration. Keep one
        # resolver per worker thread rather than rebuilding it for every PTR.
        resolver = getattr(self._thread_local, "resolver", None)
        if resolver is None:
            if self.nameservers:
                resolver = dns.resolver.Resolver(configure=False)
                resolver.nameservers = self.nameservers
            else:
                resolver = dns.resolver.Resolver(configure=True)
            resolver.timeout = self.lookup_timeout
            resolver.lifetime = self.lookup_timeout
            self._thread_local.resolver = resolver
        return resolver

    def close(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)

    def lookup(self, address: str) -> ReverseDnsResult:
        """Perform one uncached PTR lookup and distinguish absence from failure."""
        address = str(address).strip()
        try:
            canonical = str(ipaddress.ip_address(address))
        except ValueError:
            return ReverseDnsResult("retry", error="invalid IP address")

        try:
            reverse_name = dns.reversename.from_address(canonical)
            answer = self._resolver().resolve(
                reverse_name,
                "PTR",
                lifetime=self.lookup_timeout,
                raise_on_no_answer=False,
            )
            if answer.rrset and len(answer):
                hostname = str(answer[0]).rstrip(".") or None
                if hostname:
                    return ReverseDnsResult("resolved", hostname=hostname)
            return ReverseDnsResult("no_ptr")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return ReverseDnsResult("no_ptr")
        except (dns.exception.DNSException, OSError, ValueError) as exc:
            detail = str(exc).strip() or exc.__class__.__name__
            return ReverseDnsResult(
                "retry",
                error=f"{exc.__class__.__name__}: {detail}"[:500],
            )

    def resolve(self, address: str) -> str | None:
        address = str(address).strip()
        try:
            canonical = str(ipaddress.ip_address(address))
        except ValueError:
            return None

        hit, hostname = self._cache_get(canonical)
        if hit:
            return hostname

        result = self.lookup(canonical)
        hostname = result.hostname if result.status == "resolved" else None
        self._cache_put(canonical, hostname)
        return hostname

    def resolve_many(self, addresses) -> dict[str, str | None]:
        unique: list[str] = []
        result: dict[str, str | None] = {}
        seen: set[str] = set()

        for raw in addresses:
            address = str(raw or "").strip()
            try:
                canonical = str(ipaddress.ip_address(address))
            except ValueError:
                continue
            if canonical in seen:
                continue
            seen.add(canonical)
            unique.append(canonical)

            hit, hostname = self._cache_get(canonical)
            if hit:
                result[canonical] = hostname

        missing = [address for address in unique if address not in result]
        if not missing:
            return result

        futures = {
            self._executor.submit(self.resolve, address): address
            for address in missing
        }
        done, _pending = wait(futures, timeout=self.page_budget)

        for future in done:
            address = futures[future]
            try:
                result[address] = future.result()
            except Exception:
                result[address] = None

        # Pending lookups are allowed to finish in the background and populate the
        # cache. The current page remains responsive and simply shows "No PTR"
        # until a future render can use the completed cached result.
        for address in missing:
            result.setdefault(address, None)

        return result
