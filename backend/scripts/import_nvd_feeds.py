"""Download and import official NVD CVE JSON 2.0 feeds into VulnX.

Full imports resume at the last successfully completed annual feed. If a run is
interrupted inside a feed, that feed is downloaded and replayed safely: CVEs are
upserted in committed batches, so already-written batches are retained.
"""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from sqlalchemy import Column, DateTime, MetaData, String, Table, func, select, delete

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.db import engine
from app.ingest.nvd_ingest import ingest_nvd_gz

BASE_URL = "https://nvd.nist.gov/feeds/json/cve/2.0"
USER_AGENT = "VulnX-NVD-feed-import/1.1 (GitHub Actions)"
metadata = MetaData()
checkpoints = Table(
    "nvd_import_checkpoints",
    metadata,
    Column("feed_name", String(120), primary_key=True),
    Column("completed_at", DateTime, nullable=False, server_default=func.now()),
)


def download_feed(feed_name: str, destination: Path) -> None:
    url = f"{BASE_URL}/{feed_name}"
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    last_error: Exception | None = None
    for attempt in range(1, 4):
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                if response.status != 200:
                    raise RuntimeError(f"Unexpected HTTP status {response.status} for {feed_name}")
                with destination.open("wb") as output:
                    while True:
                        chunk = response.read(1024 * 1024)
                        if not chunk:
                            break
                        output.write(chunk)
            if destination.stat().st_size < 100:
                raise RuntimeError(f"Downloaded feed {feed_name} is unexpectedly small")
            print(f"Downloaded {feed_name} ({destination.stat().st_size:,} bytes)", flush=True)
            return
        except (urllib.error.URLError, TimeoutError, OSError, RuntimeError) as exc:
            last_error = exc
            destination.unlink(missing_ok=True)
            if attempt < 3:
                wait_seconds = attempt * 5
                print(f"Download attempt {attempt} failed for {feed_name}: {exc}; retrying in {wait_seconds}s", flush=True)
                time.sleep(wait_seconds)
    raise RuntimeError(f"Unable to download {feed_name} after 3 attempts: {last_error}")


def completed(feed_name: str) -> bool:
    with engine.connect() as connection:
        return connection.execute(
            select(checkpoints.c.feed_name).where(checkpoints.c.feed_name == feed_name)
        ).first() is not None


def mark_completed(feed_name: str) -> None:
    with engine.begin() as connection:
        exists = connection.execute(
            select(checkpoints.c.feed_name).where(checkpoints.c.feed_name == feed_name)
        ).first()
        if exists:
            connection.execute(
                checkpoints.update().where(checkpoints.c.feed_name == feed_name).values(completed_at=func.now())
            )
        else:
            connection.execute(checkpoints.insert().values(feed_name=feed_name))


def main() -> None:
    parser = argparse.ArgumentParser(description="Import official NVD CVE 2.0 feeds into VulnX.")
    parser.add_argument("--mode", choices=("full", "incremental"), required=True)
    parser.add_argument(
        "--restart-full",
        action="store_true",
        help="Clear annual-feed checkpoints and start a full import from the earliest year.",
    )
    args = parser.parse_args()

    # Keep the checkpoint table in the same configured database as the CVE records.
    metadata.create_all(engine, tables=[checkpoints])

    if args.restart_full:
        if args.mode != "full":
            parser.error("--restart-full can only be used with --mode full")
        with engine.begin() as connection:
            connection.execute(delete(checkpoints))

    feeds: list[str] = []
    if args.mode == "full":
        current_year = time.gmtime().tm_year
        feeds.extend(f"nvdcve-2.0-{year}.json.gz" for year in range(2002, current_year + 1))
    # Always run the recent and modified feeds, even after resuming a full import.
    feeds.extend(("nvdcve-2.0-recent.json.gz", "nvdcve-2.0-modified.json.gz"))

    with tempfile.TemporaryDirectory(prefix="vulnx-nvd-") as temporary_directory:
        temp_path = Path(temporary_directory)
        for index, feed_name in enumerate(feeds, start=1):
            is_annual = feed_name.startswith("nvdcve-2.0-") and feed_name.endswith(".json.gz") and feed_name not in {
                "nvdcve-2.0-recent.json.gz", "nvdcve-2.0-modified.json.gz"
            }
            if args.mode == "full" and is_annual and not args.restart_full and completed(feed_name):
                print(f"[{index}/{len(feeds)}] Skipping completed feed {feed_name}", flush=True)
                continue

            feed_path = temp_path / feed_name
            print(f"[{index}/{len(feeds)}] Processing {feed_name}", flush=True)
            download_feed(feed_name, feed_path)
            ingest_nvd_gz(str(feed_path))
            if is_annual:
                mark_completed(feed_name)
            feed_path.unlink(missing_ok=True)

    print(f"Completed {args.mode} NVD import ({len(feeds)} planned feeds).", flush=True)


if __name__ == "__main__":
    if not os.getenv("DATABASE_URL"):
        raise SystemExit("DATABASE_URL is not set; configure it as a GitHub Actions secret.")
    main()
