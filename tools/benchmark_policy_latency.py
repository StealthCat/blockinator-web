from __future__ import annotations

import argparse
import http.client
import json
import math
import os
import statistics
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass


@dataclass(frozen=True)
class Result:
    label: str
    concurrency: int
    samples_ms: tuple[float, ...]
    elapsed_seconds: float

    @property
    def mean(self) -> float:
        return statistics.fmean(self.samples_ms)

    @property
    def requests_per_second(self) -> float:
        return (
            len(self.samples_ms) / self.elapsed_seconds
            if self.elapsed_seconds > 0
            else 0.0
        )

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
            "concurrency": self.concurrency,
            "requests": len(self.samples_ms),
            "requests_per_second": round(self.requests_per_second, 2),
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
    return http.client.HTTPConnection(parsed.hostname, port, timeout=10), path


def request_once(
    connection: http.client.HTTPConnection,
    path: str,
    headers: dict[str, str],
    payload: bytes,
) -> float:
    start = time.perf_counter_ns()
    connection.request("POST", path, body=payload, headers=headers)
    response = connection.getresponse()
    body = response.read()
    elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
    if response.status != 200:
        raise RuntimeError(
            f"HTTP {response.status}: "
            + body.decode("utf-8", errors="replace")[:300]
        )
    return elapsed_ms


def run_target(
    label: str,
    url: str,
    api_key: str,
    payload: bytes,
    warmup: int,
    requests: int,
    concurrency: int,
) -> Result:
    headers = {
        "Content-Type": "application/json",
        "X-Api-Key": api_key,
        "Connection": "keep-alive",
    }

    warm_connection, warm_path = connection_for(url)
    try:
        for _ in range(warmup):
            request_once(warm_connection, warm_path, headers, payload)
    finally:
        warm_connection.close()

    worker_counts = [
        requests // concurrency + (1 if worker < requests % concurrency else 0)
        for worker in range(concurrency)
    ]
    worker_counts = [count for count in worker_counts if count > 0]
    barrier = threading.Barrier(len(worker_counts))

    def worker_run(count: int) -> list[float]:
        connection, path = connection_for(url)
        try:
            barrier.wait(timeout=10)
            return [
                request_once(connection, path, headers, payload)
                for _ in range(count)
            ]
        finally:
            connection.close()

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=len(worker_counts)) as executor:
        samples: list[float] = []
        for values in executor.map(worker_run, worker_counts):
            samples.extend(values)
    elapsed = time.perf_counter() - started

    return Result(
        label=label,
        concurrency=concurrency,
        samples_ms=tuple(samples),
        elapsed_seconds=elapsed,
    )


def parse_levels(value: str) -> list[int]:
    levels: list[int] = []
    for raw in value.split(","):
        try:
            level = int(raw.strip())
        except ValueError as exc:
            raise argparse.ArgumentTypeError(
                "concurrency levels must be comma-separated integers"
            ) from exc
        if level < 1:
            raise argparse.ArgumentTypeError(
                "concurrency levels must be >= 1"
            )
        if level not in levels:
            levels.append(level)
    return levels


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Measure Blockinator decision throughput/latency at multiple "
            "concurrency levels, direct to Uvicorn and through Caddy."
        )
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
    parser.add_argument("--requests", type=int, default=1000)
    parser.add_argument("--warmup", type=int, default=20)
    parser.add_argument(
        "--concurrency",
        type=parse_levels,
        default=parse_levels("1,2,4,8,16,32"),
        help="comma-separated concurrency levels",
    )
    parser.add_argument(
        "--qname",
        default="benchmark.invalid",
        help="domain to evaluate; use a blocked domain to profile the match path",
    )
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
                        "name": args.qname,
                        "type": "A",
                        "class": "IN",
                    }
                ]
            },
        },
        separators=(",", ":"),
    ).encode("utf-8")

    results: dict[str, list[dict[str, float | int | str]]] = {
        "direct": [],
        "caddy": [],
    }
    for concurrency in args.concurrency:
        for label, url in (("direct", args.direct), ("caddy", args.proxy)):
            result = run_target(
                label,
                url,
                args.api_key,
                payload,
                args.warmup,
                args.requests,
                concurrency,
            )
            results[label].append(result.as_dict())

    print(json.dumps(results, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
