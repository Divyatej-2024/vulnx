import gzip
import os
import tempfile
import time
import urllib.request
from app.ingest.nvd_ingest import ingest_nvd_gz

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")

FILES = {
    "recent":  "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz",
    "modified": "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz",
}

def download_file(url, out_path):
    print(f"Downloading: {url}")
    last_error = None
    for attempt in range(1, 4):
        temp_path = None
        try:
            with urllib.request.urlopen(url, timeout=180) as response:
                expected_size = response.headers.get("Content-Length")
                expected_size = int(expected_size) if expected_size else None
                downloaded_size = 0
                with tempfile.NamedTemporaryFile(dir=os.path.dirname(out_path), delete=False) as temp_file:
                    temp_path = temp_file.name
                    while chunk := response.read(1024 * 1024):
                        temp_file.write(chunk)
                        downloaded_size += len(chunk)

            if downloaded_size < 100:
                raise ValueError("Downloaded feed is too small to be valid.")
            if expected_size is not None and downloaded_size != expected_size:
                raise IOError(
                    f"Incomplete download: received {downloaded_size} of {expected_size} bytes."
                )

            # Reading to EOF checks the gzip trailer and catches truncated/corrupt feeds.
            with gzip.open(temp_path, "rb") as compressed:
                while compressed.read(1024 * 1024):
                    pass

            os.replace(temp_path, out_path)
            print(f"Saved and verified {out_path} ({downloaded_size:,} bytes)")
            return
        except Exception as error:
            last_error = error
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)
            if attempt < 3:
                delay = attempt * 5
                print(f"Download attempt {attempt} failed: {error}. Retrying in {delay}s...")
                time.sleep(delay)

    raise RuntimeError(f"Could not download a complete NVD feed from {url}: {last_error}") from last_error

def update_nvd():
    os.makedirs(DATA_DIR, exist_ok=True)
    print("=== Updating NVD Feeds ===")

    for name, url in FILES.items():
        out_path = os.path.join(DATA_DIR, f"{name}.json.gz")
        download_file(url, out_path)

    print("\n=== Ingesting Feeds ===")
    for name in FILES:
        ingest_nvd_gz(os.path.join(DATA_DIR, f"{name}.json.gz"))

    print("\n=== Update complete ===")

if __name__ == "__main__":
    update_nvd()
