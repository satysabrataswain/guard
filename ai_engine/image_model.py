"""
Image and Video Forensic Detection Engine.

Analyzes:
- Images
- Videos
- Metadata
- Basic manipulation indicators
- Face-related indicators

This is an explainable forensic foundation.
A trained computer-vision/deepfake model can be integrated later.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


# ---------------------------------------------------------
# Constants
# ---------------------------------------------------------

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


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------

def _clamp_score(score: float) -> float:
    return round(max(0.0, min(100.0, float(score))), 2)


def _get_severity(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "SAFE"


def _validate_file(
    file_name: str,
    file_size: int,
    media_type: str,
) -> tuple[bool, str]:

    if not file_name:
        return False, "File name is required."

    if file_size <= 0:
        return False, "File is empty."

    if file_size > MAX_FILE_SIZE:
        return False, "File size exceeds the 20 MB limit."

    extension = Path(file_name).suffix.lower()

    if media_type == "image":
        if extension not in IMAGE_EXTENSIONS:
            return False, "Unsupported image format."

    elif media_type == "video":
        if extension not in VIDEO_EXTENSIONS:
            return False, "Unsupported video format."

    else:
        return False, "Unsupported media type."

    return True, ""


# ---------------------------------------------------------
# Image analysis
# ---------------------------------------------------------

def analyze_image(
    file_name: str,
    file_size: int,
    *,
    face_detected: bool = False,
    multiple_faces: bool = False,
    face_manipulation_indicator: bool = False,
    lighting_inconsistency: bool = False,
    edge_artifact_indicator: bool = False,
    compression_anomaly: bool = False,
    metadata_missing: bool = False,
    identity_match_indicator: bool = False,
    face_swap_indicator: bool = False,
    suspicious_face_region: bool = False,
    visual_mismatch_indicator: bool = False,
) -> dict[str, Any]:

    is_valid, error = _validate_file(
        file_name,
        file_size,
        "image",
    )

    if not is_valid:
        return {
            "analysis_type": "image_forensics",
            "is_valid": False,
            "risk_score": 0.0,
            "severity": "SAFE",
            "prediction": "INVALID_INPUT",
            "confidence": 0.0,
            "indicators": [],
            "features": {},
            "recommendation": error,
        }

    score = 0.0
    indicators: list[str] = []

    # -----------------------------------------------------
    # Face analysis
    # -----------------------------------------------------

    if face_detected:
        indicators.append("Face detected in the image.")

    if multiple_faces:
        score += 5
        indicators.append(
            "Multiple faces detected in the image."
        )

    # -----------------------------------------------------
    # Manipulation indicators
    # -----------------------------------------------------

    if face_manipulation_indicator:
        score += 30
        indicators.append(
            "Possible facial manipulation detected."
        )

    if face_swap_indicator:
        score += 30
        indicators.append(
            "Possible face-swap indicator detected."
        )

    if suspicious_face_region:
        score += 20
        indicators.append(
            "Suspicious alteration detected around a facial region."
        )

    if visual_mismatch_indicator:
        score += 20
        indicators.append(
            "Visual identity mismatch indicator detected."
        )

    # -----------------------------------------------------
    # Image forensic indicators
    # -----------------------------------------------------

    if lighting_inconsistency:
        score += 15
        indicators.append(
            "Lighting or shadow inconsistency detected."
        )

    if edge_artifact_indicator:
        score += 20
        indicators.append(
            "Possible edge or blending artifact detected."
        )

    if compression_anomaly:
        score += 15
        indicators.append(
            "Unusual compression pattern detected."
        )

    if metadata_missing:
        score += 3
        indicators.append(
            "Image metadata is missing or unavailable."
        )

    # -----------------------------------------------------
    # Correlation rules
    # -----------------------------------------------------

    if face_manipulation_indicator and edge_artifact_indicator:
        score += 15
        indicators.append(
            "Facial manipulation combined with blending artifacts."
        )

    if face_swap_indicator and visual_mismatch_indicator:
        score += 15
        indicators.append(
            "Face-swap and visual identity mismatch detected together."
        )

    if lighting_inconsistency and edge_artifact_indicator:
        score += 10
        indicators.append(
            "Lighting inconsistency combined with edge artifacts."
        )

    if (
        face_manipulation_indicator
        and compression_anomaly
        and lighting_inconsistency
    ):
        score += 15
        indicators.append(
            "Multiple independent forensic indicators detected."
        )

    score = _clamp_score(score)
    severity = _get_severity(score)

    # -----------------------------------------------------
    # Prediction
    # -----------------------------------------------------

    if score >= 80:
        prediction = "LIKELY_DEEPFAKE_OR_MANIPULATED"
    elif score >= 60:
        prediction = "HIGH_MANIPULATION_RISK"
    elif score >= 40:
        prediction = "SUSPICIOUS_IMAGE"
    elif score >= 20:
        prediction = "LOW_MANIPULATION_RISK"
    else:
        prediction = "NO_MAJOR_MANIPULATION_INDICATOR"

    # -----------------------------------------------------
    # Confidence
    # -----------------------------------------------------

    if score >= 80:
        confidence = 0.90
    elif score >= 60:
        confidence = 0.82
    elif score >= 40:
        confidence = 0.72
    elif score >= 20:
        confidence = 0.62
    else:
        confidence = 0.55

    # -----------------------------------------------------
    # Recommendation
    # -----------------------------------------------------

    if severity == "CRITICAL":
        recommendation = (
            "Quarantine the media, flag the incident and perform "
            "additional deepfake/identity verification."
        )

    elif severity == "HIGH":
        recommendation = (
            "Treat the image as suspicious and perform additional "
            "identity and forensic verification."
        )

    elif severity == "MEDIUM":
        recommendation = (
            "Review the detected forensic indicators before trusting "
            "the image for identity-sensitive purposes."
        )

    elif severity == "LOW":
        recommendation = (
            "Continue monitoring; the current indicators are weak."
        )

    else:
        recommendation = (
            "No major manipulation indicators were detected by the "
            "current forensic rules."
        )

    features = {
        "file_name": file_name,
        "file_size": file_size,
        "face_detected": bool(face_detected),
        "multiple_faces": bool(multiple_faces),
        "face_manipulation_indicator": bool(
            face_manipulation_indicator
        ),
        "lighting_inconsistency": bool(
            lighting_inconsistency
        ),
        "edge_artifact_indicator": bool(
            edge_artifact_indicator
        ),
        "compression_anomaly": bool(
            compression_anomaly
        ),
        "metadata_missing": bool(metadata_missing),
        "identity_match_indicator": bool(
            identity_match_indicator
        ),
        "face_swap_indicator": bool(
            face_swap_indicator
        ),
        "suspicious_face_region": bool(
            suspicious_face_region
        ),
        "visual_mismatch_indicator": bool(
            visual_mismatch_indicator
        ),
    }

    return {
        "analysis_type": "image_forensics",
        "is_valid": True,
        "risk_score": score,
        "severity": severity,
        "prediction": prediction,
        "confidence": confidence,
        "indicators": indicators,
        "features": features,
        "recommendation": recommendation,
    }


# ---------------------------------------------------------
# Video analysis
# ---------------------------------------------------------

def analyze_video(
    file_name: str,
    file_size: int,
    *,
    face_detected: bool = False,
    multiple_faces: bool = False,
    face_manipulation_indicator: bool = False,
    lighting_inconsistency: bool = False,
    edge_artifact_indicator: bool = False,
    compression_anomaly: bool = False,
    metadata_missing: bool = False,
    face_swap_indicator: bool = False,
    temporal_inconsistency: bool = False,
    audio_visual_mismatch: bool = False,
) -> dict[str, Any]:

    is_valid, error = _validate_file(
        file_name,
        file_size,
        "video",
    )

    if not is_valid:
        return {
            "analysis_type": "video_forensics",
            "is_valid": False,
            "risk_score": 0.0,
            "severity": "SAFE",
            "prediction": "INVALID_INPUT",
            "confidence": 0.0,
            "indicators": [],
            "features": {},
            "recommendation": error,
        }

    score = 0.0
    indicators: list[str] = []

    if face_detected:
        indicators.append("Face detected in the video.")

    if multiple_faces:
        score += 5
        indicators.append(
            "Multiple faces detected in the video."
        )

    if face_manipulation_indicator:
        score += 30
        indicators.append(
            "Possible facial manipulation detected."
        )

    if face_swap_indicator:
        score += 30
        indicators.append(
            "Possible face-swap indicator detected."
        )

    if lighting_inconsistency:
        score += 15
        indicators.append(
            "Lighting inconsistency detected across video frames."
        )

    if edge_artifact_indicator:
        score += 20
        indicators.append(
            "Possible facial edge or blending artifacts detected."
        )

    if compression_anomaly:
        score += 15
        indicators.append(
            "Unusual video compression pattern detected."
        )

    if metadata_missing:
        score += 3
        indicators.append(
            "Video metadata is missing or unavailable."
        )

    if temporal_inconsistency:
        score += 25
        indicators.append(
            "Temporal inconsistency detected between video frames."
        )

    if audio_visual_mismatch:
        score += 25
        indicators.append(
            "Possible audio-video synchronization mismatch detected."
        )

    # -----------------------------------------------------
    # Correlations
    # -----------------------------------------------------

    if face_manipulation_indicator and temporal_inconsistency:
        score += 15
        indicators.append(
            "Facial manipulation combined with temporal inconsistency."
        )

    if face_swap_indicator and audio_visual_mismatch:
        score += 15
        indicators.append(
            "Face-swap indicator combined with audio-video mismatch."
        )

    if (
        face_manipulation_indicator
        and temporal_inconsistency
        and edge_artifact_indicator
    ):
        score += 15
        indicators.append(
            "Multiple independent video-forensic indicators detected."
        )

    score = _clamp_score(score)
    severity = _get_severity(score)

    # -----------------------------------------------------
    # Prediction
    # -----------------------------------------------------

    if score >= 80:
        prediction = "LIKELY_DEEPFAKE_OR_MANIPULATED"
    elif score >= 60:
        prediction = "HIGH_MANIPULATION_RISK"
    elif score >= 40:
        prediction = "SUSPICIOUS_VIDEO"
    elif score >= 20:
        prediction = "LOW_MANIPULATION_RISK"
    else:
        prediction = "NO_MAJOR_MANIPULATION_INDICATOR"

    if score >= 80:
        confidence = 0.90
    elif score >= 60:
        confidence = 0.82
    elif score >= 40:
        confidence = 0.72
    elif score >= 20:
        confidence = 0.62
    else:
        confidence = 0.55

    if severity == "CRITICAL":
        recommendation = (
            "Quarantine the video, flag the incident and perform "
            "deepfake and identity verification."
        )
    elif severity == "HIGH":
        recommendation = (
            "Treat the video as suspicious and perform additional "
            "forensic verification."
        )
    elif severity == "MEDIUM":
        recommendation = (
            "Review the detected video-forensic indicators."
        )
    elif severity == "LOW":
        recommendation = (
            "Continue monitoring; the current indicators are weak."
        )
    else:
        recommendation = (
            "No major manipulation indicators were detected by the "
            "current forensic rules."
        )

    features = {
        "file_name": file_name,
        "file_size": file_size,
        "face_detected": bool(face_detected),
        "multiple_faces": bool(multiple_faces),
        "face_manipulation_indicator": bool(
            face_manipulation_indicator
        ),
        "lighting_inconsistency": bool(
            lighting_inconsistency
        ),
        "edge_artifact_indicator": bool(
            edge_artifact_indicator
        ),
        "compression_anomaly": bool(
            compression_anomaly
        ),
        "metadata_missing": bool(metadata_missing),
        "face_swap_indicator": bool(
            face_swap_indicator
        ),
        "temporal_inconsistency": bool(
            temporal_inconsistency
        ),
        "audio_visual_mismatch": bool(
            audio_visual_mismatch
        ),
    }

    return {
        "analysis_type": "video_forensics",
        "is_valid": True,
        "risk_score": score,
        "severity": severity,
        "prediction": prediction,
        "confidence": confidence,
        "indicators": indicators,
        "features": features,
        "recommendation": recommendation,
    }


# ---------------------------------------------------------
# Compatibility wrapper
# ---------------------------------------------------------

def analyze_media(
    file_name: str,
    file_size: int,
    media_type: str = "image",
    **kwargs: Any,
) -> dict[str, Any]:

    if media_type.lower() == "video":
        return analyze_video(
            file_name,
            file_size,
            **kwargs,
        )

    return analyze_image(
        file_name,
        file_size,
        **kwargs,
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