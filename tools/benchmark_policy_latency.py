from __future__ import annotations

import argparse
import http.client
import json
import math
import os
import statistics
import time
import urllib.parse
from dataclasses import dataclass


@dataclass(frozen=True)
class Result:
    label: str
    samples_ms: tuple[float, ...]

    @property
    def mean(self) -> float:
        return statistics.fmean(self.samples_ms)

    def percentile(self, percentile: float) -> float:
        values = sorted(self.samples_ms)
        if len(values) == 1:
            return values[0]
        rank = (len(values) - 1) * percentile
        lower = math.floor(rank)
        upper = math.ceil(rank)
        if lower == upper:
            return values[lower]
        fraction = rank - lower
        return values[lower] + (values[upper] - values[lower]) * fraction

    def as_dict(self) -> dict[str, float | int | str]:
        return {
            "label": self.label,
            "requests": len(self.samples_ms),
            "mean_ms": round(self.mean, 4),
            "p50_ms": round(self.percentile(0.50), 4),
            "p95_ms": round(self.percentile(0.95), 4),
            "p99_ms": round(self.percentile(0.99), 4),
        }


def connection_for(url: str) -> tuple[http.client.HTTPConnection, str]:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "http" or not parsed.hostname:
        raise ValueError("Benchmark URLs must use http://")
    port = parsed.port or 80
    path = parsed.path or "/api/v1/decision"
    if parsed.query:
        path += "?" + parsed.query
    return http.client.HTTPConnection(parsed.hostname, port, timeout=5), path


def run_target(
    label: str,
    url: str,
    api_key: str,
    payload: bytes,
    warmup: int,
    requests: int,
) -> Result:
    connection, path = connection_for(url)
    headers = {
        "Content-Type": "application/json",
        "X-Api-Key": api_key,
        "Connection": "keep-alive",
    }

    try:
        for _ in range(warmup):
            connection.request("POST", path, body=payload, headers=headers)
            response = connection.getresponse()
            body = response.read()
            if response.status != 200:
                raise RuntimeError(
                    f"{label} warmup returned HTTP {response.status}: "
                    + body.decode("utf-8", errors="replace")[:300]
                )

        samples: list[float] = []
        for _ in range(requests):
            start = time.perf_counter_ns()
            connection.request("POST", path, body=payload, headers=headers)
            response = connection.getresponse()
            body = response.read()
            elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
            if response.status != 200:
                raise RuntimeError(
                    f"{label} returned HTTP {response.status}: "
                    + body.decode("utf-8", errors="replace")[:300]
                )
            samples.append(elapsed_ms)
        return Result(label, tuple(samples))
    finally:
        connection.close()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare Blockinator decision latency direct to Uvicorn vs through Caddy."
    )
    parser.add_argument(
        "--direct",
        default="http://127.0.0.1:8080/api/v1/decision",
    )
    parser.add_argument(
        "--proxy",
        default="http://caddy:80/api/v1/decision",
    )
    parser.add_argument(
        "--api-key",
        default=os.getenv("POLICY_API_KEY", ""),
    )
    parser.add_argument("--requests", type=int, default=200)
    parser.add_argument("--warmup", type=int, default=20)
    args = parser.parse_args()

    if not args.api_key:
        raise SystemExit("POLICY_API_KEY or --api-key is required")
    if args.requests < 1 or args.warmup < 0:
        raise SystemExit("--requests must be >=1 and --warmup must be >=0")

    payload = json.dumps(
        {
            "server_id": "latency-benchmark",
            "protocol": "udp",
            "client": {"ip": "192.0.2.10", "port": 53000},
            "dns": {
                "questions": [
                    {
                        "name": "benchmark.invalid",
                        "type": "A",
                        "class": "IN",
                    }
                ]
            },
        },
        separators=(",", ":"),
    ).encode("utf-8")

    direct = run_target(
        "direct",
        args.direct,
        args.api_key,
        payload,
        args.warmup,
        args.requests,
    )
    proxied = run_target(
        "caddy",
        args.proxy,
        args.api_key,
        payload,
        args.warmup,
        args.requests,
    )

    direct_stats = direct.as_dict()
    proxied_stats = proxied.as_dict()
    overhead = {
        "mean_ms": round(proxied.mean - direct.mean, 4),
        "p50_ms": round(
            proxied.percentile(0.50) - direct.percentile(0.50), 4
        ),
        "p95_ms": round(
            proxied.percentile(0.95) - direct.percentile(0.95), 4
        ),
        "p99_ms": round(
            proxied.percentile(0.99) - direct.percentile(0.99), 4
        ),
    }

    result = {
        "direct": direct_stats,
        "caddy": proxied_stats,
        "proxy_overhead": overhead,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
