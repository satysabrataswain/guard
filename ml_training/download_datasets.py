"""Download and prepare public Cyber Guard training datasets.

Run from the backend root:

    python -m ml_training.download_datasets

Only sources with stable public download URLs are automated. Large datasets
with multi-part files or terms/registration requirements are printed for
manual download; the script never bypasses access controls.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "datasets"

EMBER_URL = "https://ember.elastic.co/ember_dataset_2018_2.tar.bz2"
EMBER_TARGET = DATA / "malware" / "ember" / "ember_dataset_2018_2.tar.bz2"
EMBER_SHA256 = (
    "b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812"
)

MANUAL = {
    "MLAAD-tiny voice subset (500 samples prepared by project script)": "https://huggingface.co/datasets/mueller91/MLAAD-tiny",
    "ASVspoof 2021 DF (large, manual)": "https://zenodo.org/records/4835108",
    "ASVspoof 2021 PA": "https://zenodo.org/records/4834716",
    "ASVspoof 2019 / AASIST training": "https://github.com/clovaai/aasist",
    "FaceForensics++": "https://github.com/ondyari/FaceForensics",
    "DFDC": "https://ai.meta.com/datasets/dfdc/",
    "CIC-IDS2017": "https://www.unb.ca/cic/datasets/ids-2017.html",
    "PhishTank": "https://phishtank.org/developer_info.php",
    "Enron Email": "https://www.cs.cmu.edu/~enron/",
    "SpamAssassin public corpus": "https://spamassassin.apache.org/publiccorpus/",
}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def download_ember(target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)

    curl = shutil.which("curl.exe") or shutil.which("curl")
    if not curl:
        raise RuntimeError(
            "curl.exe was not found. Install/use Windows curl and rerun."
        )

    if target.exists():
        size = target.stat().st_size
        print(
            f"[found] {target} "
            f"({size / (1024 ** 3):.2f} GiB). Verifying SHA256..."
        )
        actual = sha256(target)
        if actual == EMBER_SHA256:
            print("[ok] ember2018: existing file is valid")
            return

        print(
            "[warning] Existing EMBER file is incomplete or corrupted. "
            "Removing it before a clean download."
        )
        target.unlink()

    print(f"[download] {EMBER_URL}")
    print("[info] EMBER 2018 is a large dataset; progress will be shown below.")

    result = subprocess.run(
        [
            curl,
            "-L",
            "--fail",
            "--retry",
            "3",
            "--retry-delay",
            "5",
            "--progress-bar",
            EMBER_URL,
            "-o",
            str(target),
        ],
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"curl download failed with exit code {result.returncode}"
        )

    actual = sha256(target)
    if actual != EMBER_SHA256:
        raise RuntimeError(
            f"ember2018: SHA256 mismatch. expected={EMBER_SHA256}, actual={actual}"
        )

    print(f"[saved] {target}")
    print("[ok] ember2018")


def main() -> None:
    for p in [
        DATA / "voice" / "asvspoof2019_la",
        DATA / "voice" / "asvspoof2021_df",
        DATA / "voice" / "asvspoof2021_pa",
        DATA / "deepfake" / "faceforensics",
        DATA / "deepfake" / "dfdc",
        DATA / "network" / "cic_ids2017",
        DATA / "malware" / "ember",
        DATA / "phishing" / "urls",
        DATA / "phishing" / "emails",
        DATA / "behavior",
    ]:
        p.mkdir(parents=True, exist_ok=True)

    try:
        download_ember(EMBER_TARGET)
    except Exception as exc:
        print(f"[error] ember2018: {exc}")

    print("\nManual/terms-based or multi-part sources:")
    for name, url in MANUAL.items():
        print(f"  - {name}: {url}")

    print("\nAfter downloading, place each dataset under the matching datasets/ folder.")
    print("Dataset files are ignored by Git and will not be committed.")


if __name__ == "__main__":
    main()
