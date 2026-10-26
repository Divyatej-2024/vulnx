"""Download and import official NVD CVE JSON 2.0 feeds into VulnX.

Run from the backend directory:
  python scripts/import_nvd_feeds.py --mode incremental
  python scripts/import_nvd_feeds.py --mode full
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

# When this file is executed directly, Python puts backend/scripts on sys.path,
# not backend/. Add the backend root so imports such as app.db resolve reliably.
BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.ingest.nvd_ingest import ingest_nvd_gz

BASE_URL = "https://nvd.nist.gov/feeds/json/cve/2.0"
USER_AGENT = "VulnX-NVD-feed-import/1.0 (GitHub Actions)"


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
            if attempt < 3:
                wait_seconds = attempt * 5
                print(f"Download attempt {attempt} failed for {feed_name}: {exc}; retrying in {wait_seconds}s", flush=True)
                time.sleep(wait_seconds)

    raise RuntimeError(f"Unable to download {feed_name} after 3 attempts: {last_error}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Import official NVD CVE 2.0 feeds into VulnX.")
    parser.add_argument("--mode", choices=("full", "incremental"), required=True)
    args = parser.parse_args()

    feeds: list[str] = []
    if args.mode == "full":
        current_year = time.gmtime().tm_year
        feeds.extend(f"nvdcve-2.0-{year}.json.gz" for year in range(2002, current_year + 1))
    feeds.extend(("nvdcve-2.0-recent.json.gz", "nvdcve-2.0-modified.json.gz"))

    # Use temporary storage so feed files are not committed to the repository or retained on the runner.
    with tempfile.TemporaryDirectory(prefix="vulnx-nvd-") as temporary_directory:
        temp_path = Path(temporary_directory)
        for index, feed_name in enumerate(feeds, start=1):
            feed_path = temp_path / feed_name
            print(f"[{index}/{len(feeds)}] Processing {feed_name}", flush=True)
            download_feed(feed_name, feed_path)
            ingest_nvd_gz(str(feed_path))
            feed_path.unlink(missing_ok=True)

    print(f"Completed {args.mode} NVD import ({len(feeds)} feeds).", flush=True)


if __name__ == "__main__":
    if not os.getenv("DATABASE_URL"):
        raise SystemExit("DATABASE_URL is not set; configure it as a GitHub Actions secret.")
    main()
