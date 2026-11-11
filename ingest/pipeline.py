"""One-shot: ingest a scan file, score companies, write eval metrics."""

from __future__ import annotations

import argparse
from pathlib import Path

from ingest.config import BATCH_ID
from ingest.run import ingest
from ingest.score import score_parquet, write_outputs


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="b2_download_file_by_id")
    parser.add_argument("--max-records", type=int, default=None)
    parser.add_argument("--batch-id", default=BATCH_ID)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    input_path = Path(args.input)
    if not input_path.is_absolute():
        input_path = root / input_path
    parquet_dir = root / "data" / "parquet"
    ingest(input_path, parquet_dir, args.batch_id, args.max_records)
    exported, stats = score_parquet(parquet_dir)
    write_outputs(exported, stats, root / "app" / "data" / "accounts.json", root / "data" / "score_stats.json")


if __name__ == "__main__":
    main()
