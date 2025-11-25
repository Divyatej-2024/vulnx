import os
import subprocess
import datetime

LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

def run_update():
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_file = os.path.join(LOG_DIR, f"update_{timestamp}.txt")

    cmd = ["python", "-m", "app.update_nvd"]

    with open(log_file, "w", encoding="utf-8") as f:
        process = subprocess.Popen(cmd, stdout=f, stderr=f)
        process.wait()

    print(f"Update completed. Log saved → {log_file}")

if __name__ == "__main__":
    run_update()
