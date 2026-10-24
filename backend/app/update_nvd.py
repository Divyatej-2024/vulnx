import os
import tempfile
import urllib.request
from app.ingest.nvd_ingest import ingest_nvd_gz

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")

FILES = {
    "recent":  "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz",
    "modified": "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz",
}

def download_file(url, out_path):
    print(f"Downloading: {url}")
    temp_path = None
    try:
        with urllib.request.urlopen(url, timeout=120) as response:
            with tempfile.NamedTemporaryFile(dir=os.path.dirname(out_path), delete=False) as temp_file:
                temp_path = temp_file.name
                while chunk := response.read(1024 * 1024):
                    temp_file.write(chunk)
        if os.path.getsize(temp_path) < 100:
            raise ValueError("Downloaded feed is too small to be valid.")
        os.replace(temp_path, out_path)
        print(f"Saved {out_path}")
    except Exception:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
        raise

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
