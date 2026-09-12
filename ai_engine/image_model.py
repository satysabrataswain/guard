"""
Advanced Deepfake Detection Engine.

Pipeline:

Image/Video
    ↓
Face Detection
    ↓
Face Crop
    ↓
EfficientNet
    ↓
Xception
    ↓
Vision Transformer
    ↓
Ensemble Fusion
    ↓
Deepfake Probability
    ↓
Risk Classification

Video additionally:
    ↓
Frame Sampling
    ↓
Frame-level AI inference
    ↓
Temporal consistency analysis
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ai_engine.deepfake_models import (
    get_model_ensemble,
)

from ai_engine.media_pipeline import (
    prepare_image,
    prepare_video,
)


MAX_FILE_SIZE = 20 * 1024 * 1024

IMAGE_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".webp",
}

VIDEO_EXTENSIONS = {
    ".mp4",
    ".mov",
    ".avi",
    ".mkv",
    ".webm",
}


def _clamp(
    value: float,
) -> float:

    return round(
        max(
            0.0,
            min(
                100.0,
                float(value),
            ),
        ),
        2,
    )


def _severity(
    score: float,
) -> str:

    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 40:
        return "MEDIUM"

    if score >= 20:
        return "LOW"

    return "SAFE"


def _prediction(
    score: float,
) -> str:

    if score >= 80:
        return (
            "LIKELY_DEEPFAKE_OR_MANIPULATED"
        )

    if score >= 60:
        return (
            "HIGH_MANIPULATION_RISK"
        )

    if score >= 40:
        return "SUSPICIOUS_MEDIA"

    if score >= 20:
        return "LOW_MANIPULATION_RISK"

    return (
        "NO_MAJOR_MANIPULATION_INDICATOR"
    )


def _confidence(
    score: float,
) -> float:

    if score >= 80:
        return 0.90

    if score >= 60:
        return 0.82

    if score >= 40:
        return 0.72

    if score >= 20:
        return 0.62

    return 0.55


def _model_score(
    result: dict[str, Any],
) -> float:

    scores = result[
        "ensemble_scores"
    ]

    if not scores:
        return 0.0

    return sum(scores) / len(scores)


def _temporal_score(
    frame_scores: list[float],
) -> float:

    if len(frame_scores) < 2:
        return 0.0

    average = sum(
        frame_scores
    ) / len(frame_scores)

    variance = sum(
        (
            score - average
        ) ** 2
        for score in frame_scores
    ) / len(frame_scores)

    # Large frame-to-frame changes
    # can be a temporal warning signal.
    volatility = min(
        30.0,
        variance ** 0.5,
    )

    return round(
        volatility,
        2,
    )


def _recommendation(
    severity: str,
) -> str:

    if severity == "CRITICAL":

        return (
            "Quarantine the media, flag the incident "
            "and perform identity verification."
        )

    if severity == "HIGH":

        return (
            "Treat the media as highly suspicious and "
            "perform additional forensic verification."
        )

    if severity == "MEDIUM":

        return (
            "Review the AI model evidence before trusting "
            "the media."
        )

    if severity == "LOW":

        return (
            "Continue monitoring; manipulation probability "
            "is currently low."
        )

    return (
        "No major manipulation indicator was detected."
    )


def analyze_image(
    file_name: str,
    file_size: int,
) -> dict[str, Any]:

    extension = Path(
        file_name
    ).suffix.lower()

    if not file_name:

        return {
            "is_valid": False,
            "prediction": "INVALID_INPUT",
            "risk_score": 0.0,
            "severity": "SAFE",
            "error": "File name is required.",
        }

    if file_size <= 0:

        return {
            "is_valid": False,
            "prediction": "INVALID_INPUT",
            "risk_score": 0.0,
            "severity": "SAFE",
            "error": "File is empty.",
        }

    if file_size > MAX_FILE_SIZE:

        return {
            "is_valid": False,
            "prediction": "INVALID_INPUT",
            "risk_score": 0.0,
            "severity": "SAFE",
            "error": "File size exceeds 20 MB.",
        }

    if extension not in IMAGE_EXTENSIONS:

        return {
            "is_valid": False,
            "prediction": "INVALID_INPUT",
            "risk_score": 0.0,
            "severity": "SAFE",
            "error": "Unsupported image format.",
        }

    # The API will provide a temporary path through
    # analyze_image_file() below.
    return {
        "is_valid": True,
        "prediction": "READY_FOR_AI_ANALYSIS",
        "risk_score": 0.0,
        "severity": "SAFE",
    }


def analyze_image_file(
    file_path: str,
    file_name: str,
    file_size: int,
) -> dict[str, Any]:

    basic = analyze_image(
        file_name,
        file_size,
    )

    if not basic["is_valid"]:
        return basic

    pipeline = prepare_image(
        file_path
    )

    if not pipeline["success"]:

        return {
            "is_valid": False,
            "prediction": "MEDIA_READ_ERROR",
            "risk_score": 0.0,
            "severity": "SAFE",
            "error": pipeline["error"],
        }

    if not pipeline["tensors"]:

        return {
            "is_valid": True,
            "prediction": "NO_FACE_DETECTED",
            "risk_score": 0.0,
            "severity": "SAFE",
            "confidence": 0.50,
            "indicators": [
                "No detectable face was found."
            ],
            "features": {
                "face_detected": False,
                "face_count": 0,
            },
            "recommendation": (
                "No face was available for deepfake "
                "face analysis."
            ),
        }

    import torch

    batch = torch.stack(
        pipeline["tensors"]
    )

    ensemble = get_model_ensemble()

    model_result = ensemble.predict(
        batch
    )

    score = _clamp(
        _model_score(
            model_result
        )
    )

    severity = _severity(
        score
    )

    indicators = []

    if score >= 60:
        indicators.append(
            "Multiple AI models indicate elevated manipulation probability."
        )

    if score >= 80:
        indicators.append(
            "Ensemble prediction strongly indicates possible deepfake manipulation."
        )

    if not model_result[
        "is_fine_tuned"
    ]:
        indicators.append(
            "Models are using pretrained backbone weights; "
            "deepfake-specific fine-tuning is still required."
        )

    return {
        "analysis_type": "advanced_deepfake_image",
        "is_valid": True,
        "risk_score": score,
        "severity": severity,
        "prediction": _prediction(score),
        "confidence": _confidence(score),
        "indicators": indicators,
        "features": {
            "face_detected": True,
            "face_count": pipeline[
                "face_count"
            ],
            "models_used": model_result[
                "models_used"
            ],
            "fine_tuned_models": model_result[
                "fine_tuned_models"
            ],
            "model_predictions": model_result[
                "model_predictions"
            ],
            "ensemble_score": score,
            "device": model_result[
                "device"
            ],
        },
        "recommendation": _recommendation(
            severity
        ),
    }


def analyze_video_file(
    file_path: str,
    file_name: str,
    file_size: int,
    max_frames: int = 16,
) -> dict[str, Any]:

    extension = Path(
        file_name
    ).suffix.lower()

    if file_size <= 0:
        return {
            "is_valid": False,
            "prediction": "INVALID_INPUT",
            "risk_score": 0.0,
            "severity": "SAFE",
            "error": "Video is empty.",
        }

    if file_size > MAX_FILE_SIZE:
        return {
            "is_valid": False,
            "prediction": "INVALID_INPUT",
            "risk_score": 0.0,
            "severity": "SAFE",
            "error": "Video exceeds 20 MB.",
        }

    if extension not in VIDEO_EXTENSIONS:
        return {
            "is_valid": False,
            "prediction": "INVALID_INPUT",
            "risk_score": 0.0,
            "severity": "SAFE",
            "error": "Unsupported video format.",
        }

    pipeline = prepare_video(
        file_path,
        max_frames=max_frames,
    )

    if not pipeline["tensors"]:

        return {
            "analysis_type": "advanced_deepfake_video",
            "is_valid": True,
            "risk_score": 0.0,
            "severity": "SAFE",
            "prediction": "NO_FACE_DETECTED",
            "confidence": 0.50,
            "indicators": [
                "No detectable face was found in sampled frames."
            ],
            "features": {
                "frames_analyzed": pipeline[
                    "frames_analyzed"
                ],
                "face_frames": pipeline[
                    "face_frames"
                ],
                "face_detected": False,
            },
            "recommendation": (
                "No face was available for deepfake analysis."
            ),
        }

    import torch

    batch = torch.stack(
        pipeline["tensors"]
    )

    ensemble = get_model_ensemble()

    model_result = ensemble.predict(
        batch
    )

    frame_scores = (
        model_result[
            "ensemble_scores"
        ]
    )

    spatial_score = (
        sum(frame_scores)
        / len(frame_scores)
    )

    temporal_score = _temporal_score(
        frame_scores
    )

    # Temporal signal has a lower weight because
    # volatility alone is not proof of a deepfake.
    final_score = _clamp(
        (
            spatial_score * 0.85
            + temporal_score * 0.15
        )
    )

    severity = _severity(
        final_score
    )

    indicators = [
        f"{len(frame_scores)} face frames analyzed by AI ensemble."
    ]

    if temporal_score >= 15:
        indicators.append(
            "Elevated temporal inconsistency signal detected."
        )

    if final_score >= 60:
        indicators.append(
            "AI ensemble indicates elevated deepfake probability."
        )

    if not model_result[
        "is_fine_tuned"
    ]:
        indicators.append(
            "Deepfake-specific model fine-tuning is still required."
        )

    return {
        "analysis_type": "advanced_deepfake_video",
        "is_valid": True,
        "risk_score": final_score,
        "severity": severity,
        "prediction": _prediction(
            final_score
        ),
        "confidence": _confidence(
            final_score
        ),
        "indicators": indicators,
        "features": {
            "frames_analyzed": pipeline[
                "frames_analyzed"
            ],
            "face_frames": pipeline[
                "face_frames"
            ],
            "face_detected": pipeline[
                "face_detected"
            ],
            "multiple_faces": pipeline[
                "multiple_faces"
            ],
            "frame_scores": frame_scores,
            "temporal_score": temporal_score,
            "spatial_score": round(
                spatial_score,
                2,
            ),
            "models_used": model_result[
                "models_used"
            ],
            "fine_tuned_models": model_result[
                "fine_tuned_models"
            ],
            "model_predictions": model_result[
                "model_predictions"
            ],
            "device": model_result[
                "device"
            ],
        },
        "recommendation": _recommendation(
            severity
        ),
    }


# Compatibility function.
def analyze_media(
    file_name: str,
    file_size: int,
    media_type: str = "image",
    **kwargs: Any,
) -> dict[str, Any]:

    if media_type.lower() == "video":

        return analyze_video_file(
            kwargs["file_path"],
            file_name,
            file_size,
            kwargs.get(
                "max_frames",
                16,
            ),
        )

    return analyze_image_file(
        kwargs["file_path"],
        file_name,
        file_size,
    )


def predict(
    file_name: str,
    file_size: int,
    media_type: str = "image",
    **kwargs: Any,
) -> dict[str, Any]:

    return analyze_media(
        file_name,
        file_size,
        media_type,
        **kwargs,
    )