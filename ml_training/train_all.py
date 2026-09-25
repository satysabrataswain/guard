"""Run the Cyber Guard training pipeline.

This command trains modules whose datasets are already present. Missing
datasets are reported instead of silently creating fake training data.

Usage:
    python -m ml_training.train_all
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(module: str, *args: str) -> int:
    cmd = [sys.executable, "-m", module, *args]
    print("\n$", " ".join(cmd))
    return subprocess.call(cmd, cwd=ROOT)


def main() -> None:
    steps = [
        ("ml_training.train_tabular", "--phishing-url"),
        ("ml_training.train_email",),
        ("ml_training.train_media", "--image", "--max-samples", "10000"),
        ("ml_training.train_media", "--video", "--max-samples", "10000"),
        ("ml_training.train_voice_small", "--max-samples", "10000"),
    ]

    failures = []
    for module, *args in steps:
        code = run(module, *args)
        if code != 0:
            failures.append(f"{module} {' '.join(args)}")

    print("\nTraining summary")
    if failures:
        print("Not trained because required data/dependencies are missing:")
        for item in failures:
            print(" -", item)
        print("\nMedia and voice are intentionally separate because they require")
        print("large datasets and longer GPU training.")
        print("Use:")
        print("  python -m ml_training.train_media --image")
        print("  python -m ml_training.train_media --video")
        print("  python -m ml_training.train_voice --setup")
        print("  python -m ml_training.train_voice --train")
    else:
        print("All tabular/text training jobs completed.")


if __name__ == "__main__":
    main()
