"""
Evaluate trained deepfake detection models.

Metrics:
- Accuracy
- Precision
- Recall
- F1
- Confusion Matrix
- Classification Report

Models:
- EfficientNet
- Xception
- ViT
"""

from __future__ import annotations

import argparse
from pathlib import Path

import torch
import torch.nn.functional as F

from torch.utils.data import DataLoader
from torchvision import datasets, transforms

import timm

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)


BASE_DIR = Path(
    __file__
).resolve().parent.parent


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


DEVICE = torch.device(
    "cuda"
    if torch.cuda.is_available()
    else "cpu"
)


IMAGE_SIZE = 224


MODELS = {
    "efficientnet": {
        "architecture":
            "tf_efficientnet_b0",

        "checkpoint":
            MODEL_DIR
            / "efficientnet_deepfake.pth",
    },

    "xception": {
        "architecture":
            "xception",

        "checkpoint":
            MODEL_DIR
            / "xception_deepfake.pth",
    },

    "vit": {
        "architecture":
            "vit_base_patch16_224",

        "checkpoint":
            MODEL_DIR
            / "vit_deepfake.pth",
    },
}


TEST_TRANSFORM = transforms.Compose(
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


def load_model(
    model_name: str,
):

    config = MODELS[
        model_name
    ]

    checkpoint_path = (
        config["checkpoint"]
    )

    if not checkpoint_path.exists():

        raise FileNotFoundError(
            f"Checkpoint not found: "
            f"{checkpoint_path}"
        )

    model = timm.create_model(
        config["architecture"],
        pretrained=False,
        num_classes=2,
    )

    checkpoint = torch.load(
        checkpoint_path,
        map_location=DEVICE,
    )

    state_dict = checkpoint.get(
        "model_state_dict",
        checkpoint,
    )

    model.load_state_dict(
        state_dict,
        strict=True,
    )

    model.to(
        DEVICE
    )

    model.eval()

    return model


def load_test_dataset(
    dataset_path: Path,
    batch_size: int,
):

    test_path = (
        dataset_path
        / "test"
    )

    if not test_path.exists():

        raise FileNotFoundError(
            f"Test dataset not found: "
            f"{test_path}"
        )

    dataset = datasets.ImageFolder(
        test_path,
        transform=TEST_TRANSFORM,
    )

    loader = DataLoader(
        dataset,
        batch_size=batch_size,
        shuffle=False,
        num_workers=0,
    )

    return (
        dataset,
        loader,
    )


def evaluate_model(
    model_name: str,
    dataset_path: Path,
    batch_size: int,
):

    print()
    print("=" * 60)

    print(
        f"Evaluating: "
        f"{model_name}"
    )

    print(
        f"Device: {DEVICE}"
    )

    print("=" * 60)

    dataset, loader = (
        load_test_dataset(
            dataset_path,
            batch_size,
        )
    )

    model = load_model(
        model_name
    )

    all_labels = []
    all_predictions = []

    all_probabilities = []

    with torch.no_grad():

        for images, labels in loader:

            images = images.to(
                DEVICE
            )

            outputs = model(
                images
            )

            probabilities = F.softmax(
                outputs,
                dim=1,
            )

            predictions = (
                outputs.argmax(
                    dim=1
                )
            )

            all_labels.extend(
                labels.tolist()
            )

            all_predictions.extend(
                predictions.cpu().tolist()
            )

            all_probabilities.extend(
                probabilities[:, 1]
                .cpu()
                .tolist()
            )

    accuracy = accuracy_score(
        all_labels,
        all_predictions,
    )

    precision = precision_score(
        all_labels,
        all_predictions,
        zero_division=0,
    )

    recall = recall_score(
        all_labels,
        all_predictions,
        zero_division=0,
    )

    f1 = f1_score(
        all_labels,
        all_predictions,
        zero_division=0,
    )

    matrix = confusion_matrix(
        all_labels,
        all_predictions,
    )

    print()

    print(
        f"Accuracy : "
        f"{accuracy * 100:.2f}%"
    )

    print(
        f"Precision: "
        f"{precision * 100:.2f}%"
    )

    print(
        f"Recall   : "
        f"{recall * 100:.2f}%"
    )

    print(
        f"F1 Score : "
        f"{f1 * 100:.2f}%"
    )

    print()

    print(
        "Confusion Matrix:"
    )

    print(
        matrix
    )

    print()

    print(
        "Classification Report:"
    )

    print(
        classification_report(
            all_labels,
            all_predictions,
            target_names=dataset.classes,
            zero_division=0,
        )
    )

    return {
        "model": model_name,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "confusion_matrix":
            matrix.tolist(),
    }


def main():

    parser = argparse.ArgumentParser(
        description=(
            "Evaluate trained "
            "deepfake models."
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
        "--batch-size",
        type=int,
        default=16,
    )

    args = parser.parse_args()

    dataset_path = Path(
        args.dataset
    )

    results = []

    if args.model == "all":

        for model_name in MODELS:

            result = evaluate_model(
                model_name,
                dataset_path,
                args.batch_size,
            )

            results.append(
                result
            )

    else:

        result = evaluate_model(
            args.model,
            dataset_path,
            args.batch_size,
        )

        results.append(
            result
        )

    print()
    print("=" * 60)
    print("FINAL MODEL COMPARISON")
    print("=" * 60)

    for result in results:

        print(
            f"{result['model']}: "
            f"Accuracy="
            f"{result['accuracy'] * 100:.2f}% | "
            f"F1="
            f"{result['f1'] * 100:.2f}%"
        )


if __name__ == "__main__":
    main()