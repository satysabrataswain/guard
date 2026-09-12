"""
Image/Video preprocessing and face detection pipeline.

Pipeline:

Media
  ↓
Face detection
  ↓
Face crop
  ↓
Alignment/preprocessing
  ↓
Model-ready tensors
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import cv2
import numpy as np
import torch
from PIL import Image
from torchvision import transforms


IMAGE_SIZE = 224


TRANSFORM = transforms.Compose(
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


def _get_detector():

    cascade_path = (
        cv2.data.haarcascades
        + "haarcascade_frontalface_default.xml"
    )

    detector = cv2.CascadeClassifier(
        cascade_path
    )

    return detector


def detect_faces(
    image: np.ndarray,
) -> list[tuple[int, int, int, int]]:

    gray = cv2.cvtColor(
        image,
        cv2.COLOR_BGR2GRAY,
    )

    detector = _get_detector()

    faces = detector.detectMultiScale(
        gray,
        scaleFactor=1.1,
        minNeighbors=5,
        minSize=(60, 60),
    )

    return [
        (
            int(x),
            int(y),
            int(w),
            int(h),
        )
        for x, y, w, h in faces
    ]


def crop_face(
    image: np.ndarray,
    face: tuple[int, int, int, int],
) -> np.ndarray:

    x, y, w, h = face

    padding_x = int(w * 0.20)
    padding_y = int(h * 0.20)

    height, width = image.shape[:2]

    x1 = max(
        0,
        x - padding_x,
    )

    y1 = max(
        0,
        y - padding_y,
    )

    x2 = min(
        width,
        x + w + padding_x,
    )

    y2 = min(
        height,
        y + h + padding_y,
    )

    return image[
        y1:y2,
        x1:x2,
    ]


def image_to_tensor(
    image: np.ndarray,
) -> torch.Tensor:

    rgb = cv2.cvtColor(
        image,
        cv2.COLOR_BGR2RGB,
    )

    pil_image = Image.fromarray(
        rgb
    )

    return TRANSFORM(
        pil_image
    )


def prepare_image(
    file_path: str | Path,
) -> dict[str, Any]:

    image = cv2.imread(
        str(file_path)
    )

    if image is None:

        return {
            "success": False,
            "error": "Unable to read image.",
            "faces": [],
            "tensors": [],
        }

    faces = detect_faces(
        image
    )

    tensors = []

    for face in faces:

        face_image = crop_face(
            image,
            face,
        )

        tensor = image_to_tensor(
            face_image
        )

        tensors.append(
            tensor
        )

    return {
        "success": True,
        "faces": faces,
        "face_count": len(faces),
        "tensors": tensors,
    }


def extract_video_frames(
    file_path: str | Path,
    max_frames: int = 16,
) -> list[np.ndarray]:

    capture = cv2.VideoCapture(
        str(file_path)
    )

    if not capture.isOpened():
        return []

    total_frames = int(
        capture.get(
            cv2.CAP_PROP_FRAME_COUNT
        )
    )

    if total_frames <= 0:
        capture.release()
        return []

    indices = np.linspace(
        0,
        total_frames - 1,
        min(
            max_frames,
            total_frames,
        ),
        dtype=int,
    )

    frames = []

    for index in indices:

        capture.set(
            cv2.CAP_PROP_POS_FRAMES,
            int(index),
        )

        success, frame = (
            capture.read()
        )

        if success:
            frames.append(
                frame
            )

    capture.release()

    return frames


def prepare_video(
    file_path: str | Path,
    max_frames: int = 16,
) -> dict[str, Any]:

    frames = extract_video_frames(
        file_path,
        max_frames=max_frames,
    )

    tensors = []
    face_counts = []
    face_frames = 0

    for frame in frames:

        faces = detect_faces(
            frame
        )

        face_counts.append(
            len(faces)
        )

        if not faces:
            continue

        face_frames += 1

        # Analyze the largest face.
        largest_face = max(
            faces,
            key=lambda item:
            item[2] * item[3],
        )

        face_image = crop_face(
            frame,
            largest_face,
        )

        tensors.append(
            image_to_tensor(
                face_image
            )
        )

    return {
        "success": True,
        "frames_analyzed": len(frames),
        "face_frames": face_frames,
        "face_counts": face_counts,
        "face_detected": face_frames > 0,
        "multiple_faces": any(
            count > 1
            for count in face_counts
        ),
        "tensors": tensors,
    }