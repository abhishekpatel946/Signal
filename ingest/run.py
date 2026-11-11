"""Stream a zstd JSONL Shodan dump into chunked Parquet.

Usage:
  python -m ingest.run --input "b2_download_file_by_id" --out data/parquet
  python -m ingest.run --max-records 200000
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import orjson
import pyarrow as pa
import pyarrow.parquet as pq
import zstandard as zstd

from ingest.config import BATCH_ID, CHUNK_ROWS
from ingest.extract import extract_host

SCHEMA = pa.schema(
    [
        pa.field("batch_id", pa.string()),
        pa.field("ip_str", pa.string()),
        pa.field("port", pa.int32()),
        pa.field("transport", pa.string()),
        pa.field("timestamp", pa.string()),
        pa.field("org", pa.string()),
        pa.field("isp", pa.string()),
        pa.field("asn", pa.string()),
        pa.field("country", pa.string()),
        pa.field("city", pa.string()),
        pa.field("hostnames", pa.list_(pa.string())),
        pa.field("domains", pa.list_(pa.string())),
        pa.field("product", pa.string()),
        pa.field("version", pa.string()),
        pa.field("tags", pa.list_(pa.string())),
        pa.field("module", pa.string()),
        pa.field("has_http", pa.bool_()),
        pa.field("has_ssl", pa.bool_()),
        pa.field("waf", pa.string()),
        pa.field("waf_protected", pa.bool_()),
        pa.field("security_contact", pa.string()),
        pa.field("vulns", pa.list_(pa.struct([
            pa.field("id", pa.string()),
            pa.field("cvss", pa.float64()),
            pa.field("epss", pa.float64()),
        ]))),
        pa.field("cvss_max", pa.float64()),
        pa.field("epss_max", pa.float64()),
        pa.field("n_vulns", pa.int32()),
        pa.field("eol", pa.bool_()),
        pa.field("self_signed", pa.bool_()),
        pa.field("is_honeypot", pa.bool_()),
        pa.field("is_cdn", pa.bool_()),
        pa.field("is_cloud", pa.bool_()),
        pa.field("dangerous", pa.string()),
        pa.field("is_iot", pa.bool_()),
        pa.field("is_malware_c2", pa.bool_()),
    ]
)


def _flush(rows: list[dict], out_dir: Path, chunk_idx: int) -> None:
    table = pa.Table.from_pylist(rows, schema=SCHEMA)
    path = out_dir / f"hosts_{chunk_idx:05d}.parquet"
    pq.write_table(table, path, compression="zstd")
    print(f"  wrote {path.name} ({len(rows)} rows)", flush=True)


def ingest(input_path: Path, out_dir: Path, batch_id: str, max_records: int | None) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    dctx = zstd.ZstdDecompressor()
    rows: list[dict] = []
    n = 0
    n_bad = 0
    chunk_idx = 0
    t0 = time.time()
    buf = b""

    with input_path.open("rb") as fh:
        with dctx.stream_reader(fh) as reader:
            while True:
                if max_records is not None and n >= max_records:
                    break
                piece = reader.read(4 * 1024 * 1024)
                if not piece:
                    break
                buf += piece
                while b"\n" in buf:
                    if max_records is not None and n >= max_records:
                        break
                    line, buf = buf.split(b"\n", 1)
                    if not line.strip():
                        continue
                    try:
                        rec = orjson.loads(line)
                    except (orjson.JSONDecodeError, ValueError):
                        n_bad += 1
                        continue
                    rows.append(extract_host(rec, batch_id))
                    n += 1
                    if n % 50_000 == 0:
                        elapsed = time.time() - t0
                        rate = n / elapsed if elapsed else 0
                        print(f"parsed {n:,} records ({rate:,.0f}/s)", flush=True)
                    if len(rows) >= CHUNK_ROWS:
                        _flush(rows, out_dir, chunk_idx)
                        chunk_idx += 1
                        rows = []
            if buf.strip() and (max_records is None or n < max_records):
                try:
                    rows.append(extract_host(orjson.loads(buf), batch_id))
                    n += 1
                except (orjson.JSONDecodeError, ValueError):
                    n_bad += 1

    if rows:
        _flush(rows, out_dir, chunk_idx)
        chunk_idx += 1

    stats = {
        "records": n,
        "bad_lines": n_bad,
        "chunks": chunk_idx,
        "seconds": round(time.time() - t0, 1),
        "batch_id": batch_id,
    }
    (out_dir / "_ingest_stats.json").write_text(json.dumps(stats, indent=2))
    print("ingest done", stats, flush=True)
    return stats


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        default="b2_download_file_by_id",
        help="Path to zstd JSONL scan file",
    )
    parser.add_argument("--out", default="data/parquet")
    parser.add_argument("--batch-id", default=BATCH_ID)
    parser.add_argument("--max-records", type=int, default=None)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    input_path = Path(args.input)
    if not input_path.is_absolute():
        input_path = root / input_path
    if not input_path.exists():
        print(f"missing input: {input_path}", file=sys.stderr)
        sys.exit(1)
    out_dir = Path(args.out)
    if not out_dir.is_absolute():
        out_dir = root / out_dir
    ingest(input_path, out_dir, args.batch_id, args.max_records)


if __name__ == "__main__":
    main()
