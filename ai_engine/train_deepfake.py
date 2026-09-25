"""
Deepfake model training / fine-tuning.

Models:
    1. EfficientNet-B0
    2. Xception
    3. Vision Transformer (ViT)

Dataset:
    train/REAL
    train/FAKE

The trained checkpoints are saved into:

ai_engine/models/
"""

from __future__ import annotations

import argparse
from pathlib import Path

import torch
import torch.nn as nn
from torch.optim import AdamW
from torch.utils.data import DataLoader
from torchvision import datasets, transforms
import timm


BASE_DIR = Path(__file__).resolve().parent.parent

DEFAULT_DATASET = (
    BASE_DIR
    / "dataset"
    / "deepfake"
)

MODEL_DIR = (
    BASE_DIR
    / "ai_engine"
    / "models"
)

MODEL_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


DEVICE = torch.device(
    "cuda"
    if torch.cuda.is_available()
    else "cpu"
)


IMAGE_SIZE = 224


MODELS = {
    "efficientnet": {
        "architecture": "tf_efficientnet_b0",
        "checkpoint": (
            MODEL_DIR
            / "efficientnet_deepfake.pth"
        ),
    },

    "xception": {
        "architecture": "xception",
        "checkpoint": (
            MODEL_DIR
            / "xception_deepfake.pth"
        ),
    },

    "vit": {
        "architecture": "vit_base_patch16_224",
        "checkpoint": (
            MODEL_DIR
            / "vit_deepfake.pth"
        ),
    },
}


TRAIN_TRANSFORM = transforms.Compose(
    [
        transforms.Resize(
            (IMAGE_SIZE, IMAGE_SIZE)
        ),

        transforms.RandomHorizontalFlip(
            p=0.5
        ),

        transforms.RandomRotation(
            8
        ),

        transforms.ColorJitter(
            brightness=0.15,
            contrast=0.15,
            saturation=0.15,
        ),

        transforms.ToTensor(),

        transforms.Normalize(
            mean=[
                0.485,
                0.456,
                0.406,
            ],
            std=[
                0.229,
                0.224,
                0.225,
            ],
        ),
    ]
)


VAL_TRANSFORM = transforms.Compose(
    [
        transforms.Resize(
            (IMAGE_SIZE, IMAGE_SIZE)
        ),

        transforms.ToTensor(),

        transforms.Normalize(
            mean=[
                0.485,
                0.456,
                0.406,
            ],
            std=[
                0.229,
                0.224,
                0.225,
            ],
        ),
    ]
)


def create_dataloaders(
    dataset_path: Path,
    batch_size: int,
    workers: int,
):

    train_path = dataset_path / "train"
    val_path = dataset_path / "val"

    if not train_path.exists():
        raise FileNotFoundError(
            f"Training dataset not found: {train_path}"
        )

    if not val_path.exists():
        raise FileNotFoundError(
            f"Validation dataset not found: {val_path}"
        )

    train_dataset = datasets.ImageFolder(
        train_path,
        transform=TRAIN_TRANSFORM,
    )

    val_dataset = datasets.ImageFolder(
        val_path,
        transform=VAL_TRANSFORM,
    )

    print(
        "Classes:",
        train_dataset.classes,
    )

    if train_dataset.classes != val_dataset.classes:
        raise ValueError(
            "Train and validation classes must match."
        )

    train_loader = DataLoader(
        train_dataset,
        batch_size=batch_size,
        shuffle=True,
        num_workers=workers,
        pin_memory=torch.cuda.is_available(),
    )

    val_loader = DataLoader(
        val_dataset,
        batch_size=batch_size,
        shuffle=False,
        num_workers=workers,
        pin_memory=torch.cuda.is_available(),
    )

    return (
        train_loader,
        val_loader,
        train_dataset,
    )


def build_model(
    architecture: str,
):

    model = timm.create_model(
        architecture,
        pretrained=True,
        num_classes=2,
    )

    return model.to(DEVICE)


def calculate_accuracy(
    outputs,
    targets,
):

    predictions = (
        outputs.argmax(
            dim=1
        )
    )

    correct = (
        predictions == targets
    ).sum().item()

    total = targets.size(0)

    return correct, total


def train_one_epoch(
    model,
    loader,
    criterion,
    optimizer,
):

    model.train()

    total_loss = 0.0
    total_correct = 0
    total_samples = 0

    for images, labels in loader:

        images = images.to(
            DEVICE,
            non_blocking=True,
        )

        labels = labels.to(
            DEVICE,
            non_blocking=True,
        )

        optimizer.zero_grad()

        outputs = model(
            images
        )

        loss = criterion(
            outputs,
            labels,
        )

        loss.backward()

        optimizer.step()

        total_loss += (
            loss.item()
            * labels.size(0)
        )

        correct, count = (
            calculate_accuracy(
                outputs,
                labels,
            )
        )

        total_correct += correct
        total_samples += count

    return (
        total_loss / total_samples,
        total_correct / total_samples,
    )


def validate(
    model,
    loader,
    criterion,
):

    model.eval()

    total_loss = 0.0
    total_correct = 0
    total_samples = 0

    with torch.no_grad():

        for images, labels in loader:

            images = images.to(
                DEVICE,
                non_blocking=True,
            )

            labels = labels.to(
                DEVICE,
                non_blocking=True,
            )

            outputs = model(
                images
            )

            loss = criterion(
                outputs,
                labels,
            )

            total_loss += (
                loss.item()
                * labels.size(0)
            )

            correct, count = (
                calculate_accuracy(
                    outputs,
                    labels,
                )
            )

            total_correct += correct
            total_samples += count

    return (
        total_loss / total_samples,
        total_correct / total_samples,
    )


def train_model(
    model_name: str,
    dataset_path: Path,
    epochs: int,
    batch_size: int,
    learning_rate: float,
    workers: int,
):

    config = MODELS[
        model_name
    ]

    print()
    print("=" * 60)
    print(
        f"Training: {model_name}"
    )
    print(
        f"Architecture: "
        f"{config['architecture']}"
    )
    print(
        f"Device: {DEVICE}"
    )
    print("=" * 60)

    (
        train_loader,
        val_loader,
        train_dataset,
    ) = create_dataloaders(
        dataset_path,
        batch_size,
        workers,
    )

    model = build_model(
        config["architecture"]
    )

    criterion = nn.CrossEntropyLoss()

    optimizer = AdamW(
        model.parameters(),
        lr=learning_rate,
        weight_decay=1e-4,
    )

    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
        optimizer,
        T_max=epochs,
    )

    best_val_accuracy = 0.0

    checkpoint_path = (
        config["checkpoint"]
    )

    for epoch in range(
        1,
        epochs + 1,
    ):

        train_loss, train_acc = (
            train_one_epoch(
                model,
                train_loader,
                criterion,
                optimizer,
            )
        )

        val_loss, val_acc = (
            validate(
                model,
                val_loader,
                criterion,
            )
        )

        scheduler.step()

        print(
            f"Epoch "
            f"{epoch}/{epochs} | "
            f"Train Loss: "
            f"{train_loss:.4f} | "
            f"Train Acc: "
            f"{train_acc * 100:.2f}% | "
            f"Val Loss: "
            f"{val_loss:.4f} | "
            f"Val Acc: "
            f"{val_acc * 100:.2f}%"
        )

        if val_acc > best_val_accuracy:

            best_val_accuracy = val_acc

            torch.save(
                {
                    "model_name":
                        model_name,

                    "architecture":
                        config[
                            "architecture"
                        ],

                    "num_classes":
                        2,

                    "class_names":
                        train_dataset.classes,

                    "model_state_dict":
                        model.state_dict(),

                    "validation_accuracy":
                        val_acc,

                    "epoch":
                        epoch,
                },
                checkpoint_path,
            )

            print(
                f"Best model saved: "
                f"{checkpoint_path}"
            )

    print()
    print(
        f"Finished {model_name}"
    )

    print(
        f"Best validation accuracy: "
        f"{best_val_accuracy * 100:.2f}%"
    )


def main():

    parser = argparse.ArgumentParser(
        description=(
            "Train advanced deepfake "
            "detection models."
        )
    )

    parser.add_argument(
        "--model",
        choices=[
            "efficientnet",
            "xception",
            "vit",
            "all",
        ],
        default="efficientnet",
    )

    parser.add_argument(
        "--dataset",
        type=str,
        default=str(
            DEFAULT_DATASET
        ),
    )

    parser.add_argument(
        "--epochs",
        type=int,
        default=5,
    )

    parser.add_argument(
        "--batch-size",
        type=int,
        default=16,
    )

    parser.add_argument(
        "--lr",
        type=float,
        default=1e-4,
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=0,
    )

    args = parser.parse_args()

    dataset_path = Path(
        args.dataset
    )

    if args.model == "all":

        for model_name in MODELS:

            train_model(
                model_name,
                dataset_path,
                args.epochs,
                args.batch_size,
                args.lr,
                args.workers,
            )

    else:

        train_model(
            args.model,
            dataset_path,
            args.epochs,
            args.batch_size,
            args.lr,
            args.workers,
        )


if __name__ == "__main__":
    main()