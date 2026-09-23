from __future__ import annotations

import argparse
import json
import math
import statistics
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from app.db import Database
from app.policy import PolicyEngine


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    rank = (len(ordered) - 1) * fraction
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return ordered[low]
    weight = rank - low
    return ordered[low] + (ordered[high] - ordered[low]) * weight


def seed_engine(domain_count: int, duplicate_lists: int) -> tuple[tempfile.TemporaryDirectory, PolicyEngine]:
    temp_dir = tempfile.TemporaryDirectory()
    db = Database(str(Path(temp_dir.name) / "benchmark.db"))

    domains = [f"host-{index}.benchmark.invalid" for index in range(domain_count)]
    with db.connect() as con:
        con.execute("BEGIN")
        for list_index in range(duplicate_lists):
            cursor = con.execute(
                "INSERT INTO blocklists(name,use_globally) VALUES(?,1)",
                (f"benchmark-{list_index}",),
            )
            list_id = int(cursor.lastrowid)
            db._insert_domain_memberships(con, list_id, domains)
            con.execute(
                "UPDATE blocklists SET entry_count=? WHERE id=?",
                (len(domains), list_id),
            )
        con.execute("COMMIT")

    return temp_dir, PolicyEngine(db)


def run_level(
    engine: PolicyEngine,
    requests: int,
    concurrency: int,
    qname: str,
) -> dict[str, float | int]:
    counts = [
        requests // concurrency + (1 if worker < requests % concurrency else 0)
        for worker in range(concurrency)
    ]
    counts = [count for count in counts if count]

    def worker(count: int) -> list[float]:
        values: list[float] = []
        for _ in range(count):
            started = time.perf_counter_ns()
            engine.decide("192.0.2.10", qname)
            values.append((time.perf_counter_ns() - started) / 1_000_000)
        return values

    started = time.perf_counter()
    samples: list[float] = []
    with ThreadPoolExecutor(max_workers=len(counts)) as executor:
        for values in executor.map(worker, counts):
            samples.extend(values)
    elapsed = time.perf_counter() - started

    return {
        "concurrency": concurrency,
        "requests": len(samples),
        "requests_per_second": round(len(samples) / elapsed, 2),
        "mean_ms": round(statistics.fmean(samples), 5),
        "p50_ms": round(percentile(samples, 0.50), 5),
        "p95_ms": round(percentile(samples, 0.95), 5),
        "p99_ms": round(percentile(samples, 0.99), 5),
    }


def parse_levels(raw: str) -> list[int]:
    return [int(value) for value in raw.split(",") if int(value) > 0]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Benchmark PolicyEngine.decide() without HTTP/Pydantic overhead."
    )
    parser.add_argument("--domains", type=int, default=100000)
    parser.add_argument("--duplicate-lists", type=int, default=4)
    parser.add_argument("--requests", type=int, default=100000)
    parser.add_argument("--concurrency", default="1,2,4,8,16")
    args = parser.parse_args()

    temp_dir, engine = seed_engine(
        max(1, args.domains),
        max(1, args.duplicate_lists),
    )
    try:
        qnames = {
            "allow": "not-listed.benchmark.invalid",
            "block": f"host-{max(1, args.domains) - 1}.benchmark.invalid",
        }
        output: dict[str, list[dict[str, float | int]]] = {}
        for label, qname in qnames.items():
            output[label] = [
                run_level(
                    engine,
                    max(1, args.requests),
                    concurrency,
                    qname,
                )
                for concurrency in parse_levels(args.concurrency)
            ]
        print(
            json.dumps(
                {
                    "domain_count": max(1, args.domains),
                    "duplicate_lists": max(1, args.duplicate_lists),
                    "results": output,
                },
                indent=2,
                sort_keys=True,
            )
        )
    finally:
        engine.close()
        temp_dir.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
