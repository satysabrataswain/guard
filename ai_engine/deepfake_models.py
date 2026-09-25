"""
Advanced Deepfake Model Ensemble.

Models:
- EfficientNet-B0
- Xception
- Vision Transformer (ViT)

IMPORTANT:
These models start from ImageNet pretrained weights.
For actual deepfake detection, the classification heads must be
fine-tuned on a real/fake deepfake dataset.

The module supports loading locally fine-tuned checkpoints.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import torch
import torch.nn as nn
import timm


DEVICE = torch.device(
    "cuda" if torch.cuda.is_available() else "cpu"
)


MODEL_DIR = (
    Path(__file__).resolve().parent / "models"
)

MODEL_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


MODEL_DIR = Path(__file__).resolve().parents[1] / "trained_models"

# Only use checkpoints that were actually trained for Cyber Guard.
# Untrained ImageNet backbones are not presented as deepfake detectors.
MODEL_CONFIGS = {
    "efficientnet_b0_trained": {
        "architecture": "efficientnet_b0",
        "checkpoint": MODEL_DIR / "deepfake_image_efficientnet_b0.pth",
        "classes": ["fake", "real"],
    },
}


class DeepfakeClassifier(nn.Module):
    """
    Binary classifier:

    0 = REAL
    1 = FAKE
    """

    def __init__(
        self,
        architecture: str,
    ):

        super().__init__()

        self.model = timm.create_model(
            architecture,
            pretrained=False,
            num_classes=2,
        )

    def forward(self, x):
        return self.model(x)


def _load_checkpoint(
    model: nn.Module,
    checkpoint_path: Path,
) -> bool:

    if not checkpoint_path.exists():
        return False

    checkpoint = torch.load(
        checkpoint_path,
        map_location=DEVICE,
        weights_only=False,
    )

    if isinstance(checkpoint, dict):

        if "state_dict" in checkpoint:
            state_dict = checkpoint["state_dict"]

        elif "model_state_dict" in checkpoint:
            state_dict = checkpoint["model_state_dict"]

        else:
            state_dict = checkpoint

    else:
        state_dict = checkpoint

    cleaned_state_dict = {}

    for key, value in state_dict.items():

        new_key = key

        if new_key.startswith("module."):
            new_key = new_key[7:]

        cleaned_state_dict[new_key] = value

    model.load_state_dict(
        cleaned_state_dict,
        strict=False,
    )

    return True


class DeepfakeModelEnsemble:

    def __init__(self):

        self.models: dict[str, nn.Module] = {}

        self.loaded_checkpoints: dict[str, bool] = {}

        self._load_models()

    def _load_models(self):

        for name, config in MODEL_CONFIGS.items():

            model = DeepfakeClassifier(
                config["architecture"]
            )

            checkpoint_loaded = _load_checkpoint(
                model,
                config["checkpoint"],
            )

            model.cyber_guard_classes = config.get("classes", ["fake", "real"])
            model.to(DEVICE)
            model.eval()

            self.models[name] = model

            self.loaded_checkpoints[name] = (
                checkpoint_loaded
            )

    @property
    def is_fine_tuned(self) -> bool:

        return any(
            self.loaded_checkpoints.values()
        )

    def predict(
        self,
        batch: torch.Tensor,
    ) -> dict[str, Any]:

        batch = batch.to(DEVICE)

        predictions = {}

        with torch.no_grad():

            for name, model in self.models.items():

                logits = model(batch)

                probabilities = torch.softmax(
                    logits,
                    dim=1,
                )

                classes = config_classes = getattr(model, "cyber_guard_classes", ["fake", "real"])
                fake_index = classes.index("fake") if "fake" in classes else 1
                fake_probability = probabilities[:, fake_index]

                predictions[name] = [
                    round(
                        float(value) * 100,
                        2,
                    )
                    for value in fake_probability
                ]

        count = batch.shape[0]

        ensemble_scores = []

        for index in range(count):

            values = [
                predictions[name][index]
                for name in predictions
            ]

            ensemble_scores.append(
                round(
                    sum(values) / len(values),
                    2,
                )
            )

        return {
            "model_predictions": predictions,
            "ensemble_scores": ensemble_scores,
            "models_used": list(
                self.models.keys()
            ),
            "fine_tuned_models": [
                name
                for name, loaded
                in self.loaded_checkpoints.items()
                if loaded
            ],
            "device": str(DEVICE),
            "is_fine_tuned": self.is_fine_tuned,
        }


_MODEL_ENSEMBLE = None


def get_model_ensemble():

    global _MODEL_ENSEMBLE

    if _MODEL_ENSEMBLE is None:
        _MODEL_ENSEMBLE = (
            DeepfakeModelEnsemble()
        )

    return _MODEL_ENSEMBLE