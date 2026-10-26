"""Bounded synthetic encrypted-checkpoint timing for the integration checkpoint.

This pads an owned in-memory database, not a real-file scan or fleet benchmark.
Run through the run's heavy-job admission; no service/keyring writes are involved.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform
import statistics
import tempfile
import time

from leakguard_vault import EncryptedScanStore


def benchmark(work: Path):
    work.mkdir(parents=True, exist_ok=True, mode=0o700)
    rows = []
    for target_mib in (4, 32, 60):
        with tempfile.TemporaryDirectory(prefix="checkpoint-", dir=work) as folder:
            path = Path(folder) / "profile.lgo"
            store = EncryptedScanStore.create(path, "synthetic-checkpoint-benchmark-passphrase")
            try:
                # Fixture construction deliberately bypasses the public scan API;
                # it measures checkpoint size/cost only, never scan throughput.
                connection = store._store.conn
                connection.execute('CREATE TABLE benchmark_padding(payload BLOB NOT NULL)')
                chunk = b"synthetic-padding:" + b"x" * (65536 - len(b"synthetic-padding:"))
                count = max(1, (target_mib * 1024 * 1024 - store._size()) // len(chunk))
                with connection:
                    connection.executemany('INSERT INTO benchmark_padding VALUES(?)', ((chunk,) for _ in range(count)))
                timings = []
                for _ in range(3):
                    start = time.perf_counter()
                    store.checkpoint()
                    timings.append(round(1000 * (time.perf_counter() - start), 3))
                status = store.status()
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                store.close()
                start = time.perf_counter()
                recovered = EncryptedScanStore.open(path, "synthetic-checkpoint-benchmark-passphrase")
                reopen_ms = round(1000 * (time.perf_counter() - start), 3)
                try:
                    recovered_rows = recovered._store.conn.execute('SELECT count(*) FROM benchmark_padding').fetchone()[0]
                finally:
                    recovered.close()
                rows.append({"target_mib": target_mib, "serialized_bytes": status["serialized_bytes"],
                             "ciphertext_bytes": path.stat().st_size, "capacity_bytes": status["capacity_bytes"],
                             "checkpoint_ms": timings, "checkpoint_median_ms": statistics.median(timings),
                             "reopen_including_kdf_ms": reopen_ms, "row_count": count,
                             "recovery_equal": recovered_rows == count,
                             "unchanged_close_preserved_ciphertext": hashlib.sha256(path.read_bytes()).hexdigest() == digest})
            finally:
                store.close()
    try:
        import resource
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        peak = int(peak if platform.system() == "Darwin" else peak * 1024)
    except ImportError:
        peak = None
    return {"schema": 1, "platform": platform.system(), "machine": platform.machine(),
            "python": platform.python_version(), "kind": "synthetic-checkpoint-cost",
            "rows": rows, "process_peak_rss_bytes": peak,
            "passed": all(row["recovery_equal"] and row["unchanged_close_preserved_ciphertext"] for row in rows)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = benchmark(args.work)
    rendered = json.dumps(result, sort_keys=True)
    if args.output:
        args.output.write_text(rendered + "\n")
    print(rendered)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
