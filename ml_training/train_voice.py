"""Prepare/train the Cyber Guard voice anti-spoofing model.

The recommended architecture is AASIST-L because it is much smaller than
the full AASIST model. The official AASIST project provides training and
evaluation code and pretrained checkpoints.

This script clones the official repository and prepares a command for
training. It does not bypass ASVspoof dataset access restrictions.

Usage:
    python -m ml_training.train_voice --setup
    python -m ml_training.train_voice --train

For the strongest reproducible training path, train on ASVspoof2019 LA first
and then evaluate/fine-tune against ASVspoof2021 DF/PA.
"""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / "ml_training" / "vendor"
AASIST = VENDOR / "aasist"


def setup() -> None:
    VENDOR.mkdir(parents=True, exist_ok=True)
    if AASIST.exists():
        print(f"[skip] {AASIST}")
        return

    subprocess.run(
        ["git", "clone", "https://github.com/clovaai/aasist.git", str(AASIST)],
        check=True,
    )
    print("[done] official AASIST training framework cloned")


def train(config: str = "AASIST-L.conf") -> None:
    setup()
    cfg = AASIST / "config" / config
    if not cfg.exists():
        raise SystemExit(f"Config not found: {cfg}")

    print("\nAASIST training requires the ASVspoof dataset in the layout expected")
    print("by the official repository. The official project documents the dataset")
    print("download/preparation steps and training command.")
    print(f"\nRun from: {AASIST}")
    print(f"python main.py --config ./config/{config}")
    print("\nFor a 4 GB GPU, start with AASIST-L and a small batch size in its config.")
    print("Do not claim production accuracy until evaluation is performed on a held-out")
    print("ASVspoof2021 DF/PA split and real-world samples.")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--setup", action="store_true")
    parser.add_argument("--train", action="store_true")
    parser.add_argument("--config", default="AASIST-L.conf")
    args = parser.parse_args()

    if args.setup:
        setup()
    if args.train:
        train(args.config)
    if not args.setup and not args.train:
        parser.error("Use --setup or --train")


if __name__ == "__main__":
    main()
