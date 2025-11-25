import pandas as pd
import os

# Get the project root (one level above ml_pipeline)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")

# Ensure the file exists
features_path = os.path.join(DATA_DIR, "../features.csv")
if not os.path.exists(features_path):
    raise FileNotFoundError(f"{features_path} does not exist. Run export_features first.")

# Read the CSV
df = pd.read_csv(features_path)

print("Loaded", len(df), "rows from features.csv")
