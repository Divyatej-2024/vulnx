import os
import urllib.request
from app.ingest.nvd_ingest import ingest_nvd_gz

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")

FILES = {
    "recent":  "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz",
    "modified": "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz",
}

def download_file(url, out_path):
    print(f"Downloading: {url}")
    try:
        urllib.request.urlretrieve(url, out_path)
        print(f"Saved → {out_path}")
    except Exception as e:
        print(f"Failed to download {url}: {e}")

def update_nvd():
    os.makedirs(DATA_DIR, exist_ok=True)
    print("=== Updating NVD Feeds ===")

    downloaded_files = []

    for name, url in FILES.items():
        out_path = os.path.join(DATA_DIR, f"{name}.json.gz")
        download_file(url, out_path)
        downloaded_files.append(out_path)

    print("\n=== Ingesting Feeds ===")
    for gz_file in downloaded_files:
        try:
            ingest_nvd_gz(gz_file)
        except Exception as e:
            print(f"Error ingesting {gz_file}: {e}")

    print("\n=== Update complete ===")

if __name__ == "__main__":
    update_nvd()
