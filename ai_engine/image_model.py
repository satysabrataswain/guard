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

from PIL import Image, ExifTags

from ai_engine.deepfake_models import (
    get_model_ensemble,
)
from ai_engine.web_image_tracking import track_image_on_public_web



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
    # This is a probability-derived confidence proxy, not a calibrated
    # confidence measurement. A score near 50 means the classifier is
    # uncertain between the two classes.
    return round(
        max(score, 100.0 - score) / 100.0,
        4,
    )


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


def _extract_metadata(file_path: str) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "available": False,
        "status": "UNAVAILABLE",
        "format": None,
        "width": None,
        "height": None,
        "mode": None,
        "has_exif": False,
        "exif_fields": [],
        "camera_make": None,
        "camera_model": None,
        "software": None,
        "datetime_original": None,
    }

    try:
        with Image.open(file_path) as image:
            metadata["format"] = image.format
            metadata["width"], metadata["height"] = image.size
            metadata["mode"] = image.mode

            exif = image.getexif()
            if exif:
                metadata["has_exif"] = True
                named = {}
                for key, value in exif.items():
                    name = ExifTags.TAGS.get(key, str(key))
                    named[name] = str(value)

                metadata["exif_fields"] = sorted(named.keys())[:30]
                metadata["camera_make"] = named.get("Make")
                metadata["camera_model"] = named.get("Model")
                metadata["software"] = named.get("Software")
                metadata["datetime_original"] = (
                    named.get("DateTimeOriginal")
                    or named.get("DateTime")
                )
                metadata["available"] = True
                metadata["status"] = "AVAILABLE"
            else:
                metadata["status"] = "NO_EXIF"

    except Exception as error:
        metadata["status"] = "READ_ERROR"
        metadata["error"] = str(error)

    return metadata


def _analyze_visual_artifacts(file_path: str) -> dict[str, Any]:
    import cv2
    result: dict[str, Any] = {
        "available": False,
        "artifact_score": 0.0,
        "signals": [],
        "metrics": {},
    }

    image = cv2.imread(str(file_path))
    if image is None:
        result["error"] = "Unable to decode image for visual analysis."
        return result

    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    height, width = gray.shape[:2]

    laplacian_variance = float(cv2.Laplacian(gray, cv2.CV_64F).var())
    brightness_mean = float(gray.mean())
    brightness_std = float(gray.std())

    edges = cv2.Canny(gray, 100, 200)
    edge_density = float((edges > 0).mean())

    # These are forensic heuristics only. They are supporting signals,
    # not proof that an image is synthetic or manipulated.
    signals: list[str] = []
    artifact_score = 0.0

    if laplacian_variance < 35:
        artifact_score += 20
        signals.append("Image has unusually smooth/low-detail regions.")
    elif laplacian_variance > 2500:
        artifact_score += 10
        signals.append("Image contains unusually strong high-frequency edges.")

    if edge_density > 0.22:
        artifact_score += 10
        signals.append("High edge density detected.")

    if brightness_std < 25:
        artifact_score += 10
        signals.append("Low local lighting variation detected.")

    if width < 256 or height < 256:
        signals.append("Low-resolution input can reduce detector reliability.")

    result.update(
        {
            "available": True,
            "artifact_score": round(min(100.0, artifact_score), 2),
            "signals": signals,
            "metrics": {
                "width": width,
                "height": height,
                "laplacian_variance": round(laplacian_variance, 2),
                "brightness_mean": round(brightness_mean, 2),
                "brightness_std": round(brightness_std, 2),
                "edge_density": round(edge_density, 4),
            },
            "note": (
                "Visual artifact metrics are supporting forensic signals "
                "and are not used as a standalone deepfake verdict."
            ),
        }
    )
    return result


def _build_face_detection(
    pipeline: dict[str, Any],
) -> dict[str, Any]:
    faces = pipeline.get("faces", [])
    return {
        "detected": bool(faces),
        "face_count": len(faces),
        "faces": [
            {
                "x": int(face[0]),
                "y": int(face[1]),
                "width": int(face[2]),
                "height": int(face[3]),
            }
            for face in faces
        ],
        "method": "OpenCV Haar Cascade",
        "note": (
            "Face detection identifies visible faces; it does not by itself "
            "determine whether a face is genuine or manipulated."
        ),
    }


def _analyze_no_face_result(
    face_detection: dict[str, Any],
    visual_artifacts: dict[str, Any],
    metadata: dict[str, Any],
) -> dict[str, Any]:
    return {
        "analysis_type": "trained_efficientnet_b0_deepfake_image",
        "is_valid": True,
        "prediction": "NO_FACE_DETECTED",
        "risk_score": 0.0,
        "severity": "SAFE",
        "confidence": 0.50,
        "indicators": [
            "No detectable face was found for face-based deepfake analysis."
        ],
        "face_detection": face_detection,
        "visual_artifacts": visual_artifacts,
        "metadata": metadata,
        "features": {
            "face_detected": False,
            "face_count": 0,
        },
        "recommendation": (
            "No face was available for the trained face-based deepfake model. "
            "Review visual and metadata signals separately."
        ),
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

    from ai_engine.media_pipeline import prepare_image

    pipeline = prepare_image(file_path)

    if not pipeline["success"]:
        return {
            "is_valid": False,
            "prediction": "MEDIA_READ_ERROR",
            "risk_score": 0.0,
            "severity": "SAFE",
            "error": pipeline["error"],
        }

    face_detection = _build_face_detection(pipeline)
    visual_artifacts = _analyze_visual_artifacts(file_path)
    metadata = _extract_metadata(file_path)
    web_presence = track_image_on_public_web(file_path)

    if not pipeline["tensors"]:
        result = _analyze_no_face_result(
            face_detection,
            visual_artifacts,
            metadata,
        )
        result["web_presence"] = web_presence
        return result

    import torch

    batch = torch.stack(pipeline["tensors"])
    ensemble = get_model_ensemble()
    model_result = ensemble.predict(batch)

    score = _clamp(_model_score(model_result))
    severity = _severity(score)

    indicators = [
        f"Trained EfficientNet-B0 fake probability: {score:.2f}/100."
    ]

    if face_detection["face_count"] > 1:
        indicators.append(
            f"{face_detection['face_count']} faces detected and analyzed."
        )

    if visual_artifacts.get("signals"):
        indicators.extend(
            f"Visual heuristic: {item}"
            for item in visual_artifacts["signals"]
        )

    if metadata.get("status") == "NO_EXIF":
        indicators.append(
            "No EXIF metadata was present in the uploaded image."
        )

    if score >= 60:
        indicators.append(
            "The trained EfficientNet-B0 model detected elevated fake-image probability."
        )
    elif score >= 40:
        indicators.append(
            "The trained EfficientNet-B0 model produced a suspicious/intermediate score; "
            "this is not a definitive deepfake verdict."
        )

    return {
        "analysis_type": "trained_efficientnet_b0_deepfake_image",
        "is_valid": True,
        "risk_score": score,
        "severity": severity,
        "prediction": _prediction(score),
        "confidence": _confidence(score),
        "indicators": indicators,
        "face_detection": face_detection,
        "visual_artifacts": visual_artifacts,
        "metadata": metadata,
        "web_presence": web_presence,
        "features": {
            "face_detected": True,
            "face_count": pipeline["face_count"],
            "models_used": model_result["models_used"],
            "fine_tuned_models": model_result["fine_tuned_models"],
            "model_predictions": model_result["model_predictions"],
            "ensemble_score": score,
            "device": model_result["device"],
        },
        "recommendation": _recommendation(severity),
    }


def _video_metadata(
    file_path: str,
    capture: Any,
    total_frames: int,
    fps: float,
) -> dict[str, Any]:
    import cv2

    width = int(capture.get(cv2.CAP_PROP_FRAME_WIDTH))
    height = int(capture.get(cv2.CAP_PROP_FRAME_HEIGHT))
    duration = (
        round(total_frames / fps, 2)
        if fps > 0 and total_frames > 0
        else None
    )

    return {
        "available": True,
        "status": "AVAILABLE",
        "format": Path(file_path).suffix.lower().lstrip(".").upper(),
        "width": width,
        "height": height,
        "fps": round(fps, 2) if fps > 0 else None,
        "frame_count": total_frames,
        "duration_seconds": duration,
        "codec": "Detected by OpenCV/FFmpeg backend",
    }


def _basic_video_heuristics(
    frames: list[Any],
    face_counts: list[int],
) -> tuple[float, dict[str, Any], list[str]]:
    import cv2

    if not frames:
        return 0.0, {}, ["No readable video frames were available."]

    brightness = [float(cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY).mean()) for frame in frames]
    sharpness = [
        float(cv2.Laplacian(
            cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY),
            cv2.CV_64F,
        ).var())
        for frame in frames
    ]
    edge_density = []
    for frame in frames:
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        edges = cv2.Canny(gray, 100, 200)
        edge_density.append(float((edges > 0).mean()))

    frame_diffs = []
    for previous, current in zip(frames, frames[1:]):
        previous_gray = cv2.cvtColor(previous, cv2.COLOR_BGR2GRAY)
        current_gray = cv2.cvtColor(current, cv2.COLOR_BGR2GRAY)
        previous_gray = cv2.resize(previous_gray, (160, 90))
        current_gray = cv2.resize(current_gray, (160, 90))
        frame_diffs.append(
            float(cv2.absdiff(previous_gray, current_gray).mean())
        )

    signals: list[str] = []
    score = 0.0

    face_frames = sum(1 for count in face_counts if count > 0)
    multiple_face_frames = sum(1 for count in face_counts if count > 1)

    if face_frames == 0:
        signals.append("No face was detected in the sampled frames.")
    else:
        face_ratio = face_frames / len(frames)
        signals.append(
            f"Face detected in {face_frames}/{len(frames)} sampled frames."
        )
        if face_ratio < 0.40:
            score += 10
            signals.append("Face visibility changed substantially across sampled frames.")

    if multiple_face_frames:
        signals.append(
            f"Multiple faces were detected in {multiple_face_frames} sampled frames."
        )

    brightness_range = max(brightness) - min(brightness)
    if brightness_range > 80:
        score += 10
        signals.append("Large frame-to-frame brightness variation detected.")

    if sharpness and sum(sharpness) / len(sharpness) < 80:
        score += 10
        signals.append("Several sampled frames contain low-detail or blurred regions.")

    if frame_diffs:
        mean_motion = sum(frame_diffs) / len(frame_diffs)
        motion_std = (
            sum((value - mean_motion) ** 2 for value in frame_diffs)
            / len(frame_diffs)
        ) ** 0.5
        if motion_std > 18:
            score += 15
            signals.append(
                "Irregular frame-to-frame visual change was detected."
            )
    else:
        mean_motion = 0.0
        motion_std = 0.0

    mean_edge_density = (
        sum(edge_density) / len(edge_density)
        if edge_density else 0.0
    )

    metrics = {
        "brightness_mean": round(sum(brightness) / len(brightness), 2),
        "brightness_range": round(brightness_range, 2),
        "sharpness_mean": round(sum(sharpness) / len(sharpness), 2),
        "edge_density_mean": round(mean_edge_density, 4),
        "mean_frame_difference": round(mean_motion, 2),
        "frame_difference_std": round(motion_std, 2),
        "sampled_frames": len(frames),
        "face_frames": face_frames,
        "multiple_face_frames": multiple_face_frames,
    }

    return min(100.0, score), metrics, signals


def analyze_video_file(
    file_path: str,
    file_name: str,
    file_size: int,
    max_frames: int = 16,
) -> dict[str, Any]:
    import cv2
    from ai_engine.media_pipeline import detect_faces

    extension = Path(file_name).suffix.lower()

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

    capture = cv2.VideoCapture(str(file_path))
    if not capture.isOpened():
        return {
            "is_valid": False,
            "prediction": "MEDIA_READ_ERROR",
            "risk_score": 0.0,
            "severity": "SAFE",
            "error": "Unable to open the video.",
        }

    total_frames = int(capture.get(cv2.CAP_PROP_FRAME_COUNT))
    fps = float(capture.get(cv2.CAP_PROP_FPS) or 0.0)
    metadata = _video_metadata(
        file_path,
        capture,
        total_frames,
        fps,
    )

    frames = []
    if total_frames > 0:
        import numpy as np
        indices = np.linspace(
            0,
            total_frames - 1,
            min(max_frames, total_frames),
            dtype=int,
        )
        for index in indices:
            capture.set(cv2.CAP_PROP_POS_FRAMES, int(index))
            ok, frame = capture.read()
            if ok and frame is not None:
                frames.append(frame)

    capture.release()

    if not frames:
        return {
            "is_valid": False,
            "prediction": "MEDIA_READ_ERROR",
            "risk_score": 0.0,
            "severity": "SAFE",
            "error": "No readable frames were found in the video.",
        }

    face_counts = [len(detect_faces(frame)) for frame in frames]
    face_detection = {
        "detected": any(count > 0 for count in face_counts),
        "face_frames": sum(1 for count in face_counts if count > 0),
        "sampled_frames": len(frames),
        "face_counts_per_frame": face_counts,
        "multiple_face_frames": sum(1 for count in face_counts if count > 1),
        "method": "OpenCV Haar Cascade",
        "note": (
            "Basic face detection only. It does not prove that a detected "
            "face is real or manipulated."
        ),
    }

    score, visual_metrics, indicators = _basic_video_heuristics(
        frames,
        face_counts,
    )

    visual_artifacts = {
        "available": True,
        "artifact_score": round(score, 2),
        "signals": indicators,
        "metrics": visual_metrics,
        "note": (
            "These are basic video heuristics. A trained video deepfake "
            "model will be added later."
        ),
    }

    severity = _severity(score)

    if score >= 60:
        prediction = "BASIC_VIDEO_SUSPICIOUS"
    elif score >= 20:
        prediction = "BASIC_VIDEO_REVIEW"
    else:
        prediction = "NO_MAJOR_BASIC_VIDEO_ANOMALY"

    return {
        "analysis_type": "basic_video_heuristic",
        "is_valid": True,
        "risk_score": round(score, 2),
        "severity": severity,
        "prediction": prediction,
        "confidence": round(
            max(score, 100.0 - score) / 100.0,
            4,
        ),
        "indicators": indicators,
        "face_detection": face_detection,
        "visual_artifacts": visual_artifacts,
        "metadata": metadata,
        "features": {
            "frames_analyzed": len(frames),
            "face_detected": face_detection["detected"],
            "face_frames": face_detection["face_frames"],
            "multiple_faces": face_detection["multiple_face_frames"] > 0,
            "heuristic_score": round(score, 2),
            "trained_video_model": False,
            "analysis_note": (
                "Basic OpenCV video analysis is active. "
                "No trained video deepfake classifier is used yet."
            ),
        },
        "recommendation": (
            "Use this result as a basic screening signal. "
            "Do not treat it as a definitive deepfake verdict until "
            "a video-specific trained model is added."
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