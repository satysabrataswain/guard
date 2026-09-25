"""Train image/video deepfake classifiers."""

from __future__ import annotations

import argparse
import random
import shutil
from pathlib import Path

import torch
from torch import nn
from torch.utils.data import DataLoader
from torchvision import datasets, transforms
import timm


ROOT = Path(__file__).resolve().parents[1]
MODELS = ROOT / "trained_models"


def get_device() -> torch.device:
    return torch.device("cuda" if torch.cuda.is_available() else "cpu")


def train_image(
    data_dir: Path,
    epochs: int = 5,
    batch_size: int = 8,
    max_samples: int = 20_000,
) -> None:

    if not data_dir.exists():
        raise SystemExit(f"Image dataset not found: {data_dir}")

    real_files = []
    fake_files = []

    for ext in ("*.jpg", "*.jpeg", "*.png", "*.webp", "*.bmp"):
        real_files.extend((data_dir / "real").glob(ext))
        fake_files.extend((data_dir / "fake").glob(ext))

    if not real_files or not fake_files:
        raise SystemExit(
            f"Both real and fake images are required under {data_dir}"
        )

    random.seed(42)
    random.shuffle(real_files)
    random.shuffle(fake_files)

    per_class = max_samples // 2

    real_files = real_files[:per_class]
    fake_files = fake_files[:per_class]

    print(f"[image] real images: {len(real_files):,}")
    print(f"[image] fake images: {len(fake_files):,}")
    print(f"[image] total images: {len(real_files) + len(fake_files):,}")

    subset = data_dir.parent / "image_train_subset"

    for cls in ("real", "fake"):
        cls_dir = subset / cls
        cls_dir.mkdir(parents=True, exist_ok=True)

    selected = [
        ("real", p) for p in real_files
    ] + [
        ("fake", p) for p in fake_files
    ]

    print("[image] preparing training subset...")

    for cls, src in selected:
        dst = subset / cls / src.name

        if not dst.exists():
            try:
                dst.hardlink_to(src)
            except OSError:
                shutil.copy2(src, dst)

    transform = transforms.Compose([
        transforms.Resize((224, 224)),
        transforms.RandomHorizontalFlip(),
        transforms.RandomResizedCrop(
            224,
            scale=(0.8, 1.0)
        ),
        transforms.ToTensor(),
        transforms.Normalize(
            [0.485, 0.456, 0.406],
            [0.229, 0.224, 0.225],
        ),
    ])

    dataset = datasets.ImageFolder(
        subset,
        transform=transform,
    )

    if len(dataset.classes) != 2:
        raise SystemExit(
            "Image dataset must contain exactly two folders: real and fake"
        )

    print(f"[image] classes: {dataset.classes}")
    print(f"[image] dataset size: {len(dataset):,}")

    loader = DataLoader(
        dataset,
        batch_size=batch_size,
        shuffle=True,
        num_workers=0,
    )

    current_device = get_device()

    print(f"[image] device: {current_device}")

    model = timm.create_model(
        "efficientnet_b0",
        pretrained=True,
        num_classes=2,
    )

    model.to(current_device)

    optimizer = torch.optim.AdamW(
        model.parameters(),
        lr=1e-4,
        weight_decay=1e-4,
    )

    loss_fn = nn.CrossEntropyLoss()

    model.train()

    for epoch in range(epochs):

        total_loss = 0.0

        for batch_index, (x, y) in enumerate(loader, start=1):

            x = x.to(current_device)
            y = y.to(current_device)

            optimizer.zero_grad(set_to_none=True)

            logits = model(x)

            loss = loss_fn(logits, y)

            loss.backward()

            optimizer.step()

            total_loss += float(loss)

            if batch_index % 100 == 0:
                print(
                    f"[image] epoch {epoch + 1}/{epochs} "
                    f"batch {batch_index}/{len(loader)} "
                    f"loss={float(loss):.4f}"
                )

        avg_loss = total_loss / max(1, len(loader))

        print(
            f"[image] epoch {epoch + 1}/{epochs} "
            f"loss={avg_loss:.4f}"
        )

    MODELS.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_file = MODELS / "deepfake_image_efficientnet_b0.pth"

    torch.save(
        {
            "model_name": "efficientnet_b0",
            "classes": dataset.classes,
            "state_dict": model.state_dict(),
        },
        output_file,
    )

    print()
    print("[done] Deepfake image model saved:")
    print(output_file)


def train_video(
    data_dir: Path,
    epochs: int = 3,
    batch_size: int = 8,
    max_samples: int = 10_000,
) -> None:

    try:
        import cv2
    except ImportError as exc:
        raise SystemExit(
            "opencv-python is required"
        ) from exc

    frame_root = data_dir.parent / "video_frames"

    for cls in ("real", "fake"):
        (frame_root / cls).mkdir(
            parents=True,
            exist_ok=True,
        )

    videos = []

    per_class = max_samples // 2

    for cls in ("real", "fake"):

        class_files = []

        for ext in (
            "*.mp4",
            "*.mov",
            "*.avi",
            "*.mkv",
            "*.webm",
        ):
            class_files.extend(
                sorted((data_dir / cls).glob(ext))
            )

        videos.extend(
            (cls, p)
            for p in class_files[:per_class]
        )

    if not videos:
        raise SystemExit(
            f"No videos found under "
            f"{data_dir / 'real'} and {data_dir / 'fake'}"
        )

    print(
        f"[video] selected {len(videos):,} videos"
    )

    for cls, video in videos:

        stem = video.stem

        output_dir = (
            frame_root / cls / stem
        )

        output_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        if any(output_dir.glob("*.jpg")):
            continue

        cap = cv2.VideoCapture(
            str(video)
        )

        total_frames = int(
            cap.get(
                cv2.CAP_PROP_FRAME_COUNT
            )
        )

        step = max(
            1,
            total_frames // 5
        )

        frame_index = 0
        saved = 0

        while True:

            ok, frame = cap.read()

            if not ok:
                break

            if frame_index % step == 0:

                cv2.imwrite(
                    str(
                        output_dir
                        / f"{saved:05d}.jpg"
                    ),
                    frame,
                )

                saved += 1

            frame_index += 1

            if saved >= 5:
                break

        cap.release()

    train_image(
        frame_root,
        epochs=epochs,
        batch_size=batch_size,
        max_samples=max_samples,
    )


def main() -> None:

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--image",
        action="store_true",
    )

    parser.add_argument(
        "--video",
        action="store_true",
    )

    parser.add_argument(
        "--data",
        type=Path,
    )

    parser.add_argument(
        "--epochs",
        type=int,
        default=5,
    )

    parser.add_argument(
        "--batch-size",
        type=int,
        default=8,
    )

    parser.add_argument(
        "--max-samples",
        type=int,
        default=20_000,
    )

    args = parser.parse_args()

    if args.image:

        train_image(
            args.data
            or ROOT
            / "datasets"
            / "deepfake"
            / "image_20000",
            args.epochs,
            args.batch_size,
            args.max_samples,
        )

    elif args.video:

        train_video(
            args.data
            or ROOT
            / "datasets"
            / "deepfake"
            / "video_dataset",
            args.epochs,
            args.batch_size,
            args.max_samples,
        )

    else:

        parser.error(
            "Use --image or --video"
        )


if __name__ == "__main__":
    main()