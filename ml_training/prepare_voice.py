"""Prepare 500 short voice deepfake samples from MLAAD-tiny.

Selects files directly from the dataset's original/ and fake/ folders instead
of streaming/decoding the full 15K-row dataset. Downloads only selected audio,
trims to <=5 seconds, converts to 16 kHz mono WAV, and creates a manifest.
"""

from __future__ import annotations

import csv
from pathlib import Path

import librosa
import numpy as np
import soundfile as sf
from huggingface_hub import HfApi, hf_hub_download

ROOT = Path(__file__).resolve().parents[1]
VOICE = ROOT / "datasets" / "voice"
REAL = VOICE / "real"
FAKE = VOICE / "fake"

DATASET_ID = "mueller91/MLAAD-tiny"
PER_CLASS = 250
MAX_SECONDS = 5
TARGET_SR = 16_000
MAX_TOTAL_BYTES = 500 * 1024 * 1024
MAX_SOURCE_FILE_BYTES = 2 * 1024 * 1024


def get_files(prefix: str):
    api = HfApi()
    files = list(api.list_repo_tree(DATASET_ID, repo_type="dataset", path_in_repo=prefix, recursive=True))
    return [
        x for x in files
        if getattr(x, "path", "").lower().endswith((".wav", ".flac", ".mp3", ".ogg"))
        and getattr(x, "size", 0) <= MAX_SOURCE_FILE_BYTES
    ]


def prepare_one(repo_path: str, out_path: Path) -> int:
    local_path = hf_hub_download(
        repo_id=DATASET_ID,
        filename=repo_path,
        repo_type="dataset",
    )
    audio, sr = librosa.load(local_path, sr=TARGET_SR, mono=True, duration=MAX_SECONDS)
    audio = np.asarray(audio, dtype=np.float32)
    sf.write(out_path, audio, TARGET_SR, subtype="PCM_16")
    return out_path.stat().st_size


def main() -> None:
    REAL.mkdir(parents=True, exist_ok=True)
    FAKE.mkdir(parents=True, exist_ok=True)

    # Start clean so an interrupted previous run cannot contaminate the manifest.
    for folder in (REAL, FAKE):
        for path in folder.glob("*.wav"):
            path.unlink()

    print(f"[voice] source: {DATASET_ID}")
    print("[voice] selecting 250 original + 250 fake files")
    print("[voice] source-file cap: 2 MB; output clip: <= 5 sec, 16 kHz mono")

    original_files = get_files("original")
    fake_files = get_files("fake")

    if len(original_files) < PER_CLASS or len(fake_files) < PER_CLASS:
        raise SystemExit(
            f"Not enough suitable source files: {len(original_files)} original, "
            f"{len(fake_files)} fake"
        )

    # Deterministic selection; source files are already organized by class.
    original_files = sorted(original_files, key=lambda x: x.path)[:PER_CLASS]
    fake_files = sorted(fake_files, key=lambda x: x.path)[:PER_CLASS]

    total_bytes = 0
    for i, info in enumerate(original_files):
        total_bytes += prepare_one(info.path, REAL / f"{i:04d}.wav")
        if (i + 1) % 25 == 0:
            print(f"[voice] {i + 1}/250 real prepared")

    for i, info in enumerate(fake_files):
        total_bytes += prepare_one(info.path, FAKE / f"{i:04d}.wav")
        if (i + 1) % 25 == 0:
            print(f"[voice] {i + 1}/250 spoof prepared")

    if total_bytes > MAX_TOTAL_BYTES:
        raise SystemExit(
            f"Output dataset exceeds 500 MB: {total_bytes / (1024 * 1024):.1f} MB"
        )

    manifest = VOICE / "voice_manifest.csv"
    with manifest.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["path", "label"])
        for path in sorted(REAL.glob("*.wav")):
            writer.writerow([path.relative_to(ROOT).as_posix(), 0])
        for path in sorted(FAKE.glob("*.wav")):
            writer.writerow([path.relative_to(ROOT).as_posix(), 1])

    print(f"[done] 250 real + 250 spoof")
    print(f"[done] audio size: {total_bytes / (1024 * 1024):.1f} MB")
    print(f"[done] manifest: {manifest}")


if __name__ == "__main__":
    main()
