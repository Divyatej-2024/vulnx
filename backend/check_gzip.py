import gzip
import json

file_path = "data/nvdcve-2.0-recent.json.gz"

with gzip.open(file_path, "rt", encoding="utf-8") as f:
    data = json.load(f)

print("Top-level keys:", list(data.keys()))
print("Number of CVE_Items:", len(data.get("CVE_Items", [])))

if data.get("CVE_Items"):
    print("First CVE ID:", data["CVE_Items"][0]["cve"]["CVE_data_meta"]["ID"])
