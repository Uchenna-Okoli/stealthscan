"""Checkpoint save/load for resumable scans."""
import json
import os
from datetime import datetime

CHECKPOINT_DIR = os.path.expanduser("~/.local/share/stealthscan/checkpoints")


def save_checkpoint(job_id, data):
    os.makedirs(CHECKPOINT_DIR, mode=0o700, exist_ok=True)
    path = os.path.join(CHECKPOINT_DIR, f"{job_id}.json")
    data["last_updated"] = datetime.utcnow().isoformat()
    with open(path, "w") as f:
        json.dump(data, f)
    os.chmod(path, 0o600)
    return path


def load_checkpoint(job_id):
    path = os.path.join(CHECKPOINT_DIR, f"{job_id}.json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)