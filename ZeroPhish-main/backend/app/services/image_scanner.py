"""Shared image processing for QR and screenshot scans."""

import re
import warnings
from io import BytesIO

import cv2
import numpy as np
from PIL import Image, UnidentifiedImageError

from backend.app.detectors.url_detector import extract_urls


class OCRUnavailableError(RuntimeError):
    """Raised when the OCR engine is unavailable."""


class OCRProcessingError(RuntimeError):
    """Raised when OCR could not process an otherwise readable image."""


MAX_IMAGE_BYTES = 10 * 1024 * 1024
MAX_IMAGE_PIXELS = 25_000_000
ALLOWED_CONTENT_TYPES = {"image/png", "image/jpeg", "image/webp", "image/bmp"}


def validate_upload(content_type: str | None, contents: bytes) -> None:
    """Reject unsupported or oversized uploads before image decoding."""
    if len(contents) > MAX_IMAGE_BYTES:
        raise ValueError("Image is too large. Please upload an image smaller than 10 MB.")
    if content_type and content_type.lower() not in ALLOWED_CONTENT_TYPES:
        raise ValueError("Unsupported image type. Please upload a PNG, JPG, WEBP, or BMP image.")
    if not contents:
        raise ValueError("Uploaded file is empty.")


def decode_image(contents: bytes) -> np.ndarray:
    validate_image_dimensions(contents)
    image = cv2.imdecode(np.frombuffer(contents, np.uint8), cv2.IMREAD_COLOR)
    if image is None:
        raise ValueError("Invalid image file. Please upload a readable image.")
    return image


def validate_image_dimensions(contents: bytes) -> None:
    """Check image dimensions from its header before allocating decoded pixels."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(BytesIO(contents)) as image:
                width, height = image.size
    except (Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
        raise ValueError(
            "Image dimensions exceed the maximum allowed size of 25 megapixels."
        ) from exc
    except (UnidentifiedImageError, OSError, ValueError) as exc:
        raise ValueError("Invalid image file. Please upload a readable image.") from exc

    if width * height > MAX_IMAGE_PIXELS:
        raise ValueError(
            "Image dimensions exceed the maximum allowed size of 25 megapixels."
        )


def preprocess_image(image: np.ndarray) -> np.ndarray:
    """Create one normalized grayscale image for QR and OCR consumers."""
    height, width = image.shape[:2]
    longest_side = max(height, width)
    if longest_side < 1200:
        scale = 1200 / longest_side
        image = cv2.resize(image, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)
    gray = image if len(image.shape) == 2 else cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    gray = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8)).apply(gray)
    return cv2.GaussianBlur(gray, (3, 3), 0)


def decode_qr(image: np.ndarray) -> tuple[bool, str | None]:
    """Try the original, normalized, and adaptive-threshold image once each."""
    candidates = [image]
    if max(image.shape[:2]) < 400:
        candidates.append(cv2.resize(image, None, fx=4, fy=4, interpolation=cv2.INTER_NEAREST))
        scale = 400 / max(image.shape[:2])
        candidates.append(cv2.resize(image, None, fx=scale, fy=scale, interpolation=cv2.INTER_NEAREST))
    candidates.append(preprocess_image(image))
    thresholded = cv2.adaptiveThreshold(
        candidates[-1], 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 31, 5
    )
    candidates.append(thresholded)
    detected = False
    for candidate in candidates:
        import zxingcpp
        try:
            results = zxingcpp.read_barcodes(candidate)
        except Exception:
            continue
        if results:
            detected = True
            text = results[0].text
            if text and text.strip():
                return True, text.strip()
    return detected, None


def classify_payload(payload: str) -> str:
    value = payload.strip()
    if re.match(r"^(?:https?://|www\.)", value, re.IGNORECASE) or re.match(
        r"^[\w.-]+\.[a-z]{2,}(?:/|$)", value, re.IGNORECASE
    ):
        return "url"
    if value.lower().startswith("mailto:") or re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", value):
        return "email"
    if value.lower().startswith("tel:") or re.match(r"^\+?[\d\s().-]{7,}$", value):
        return "phone"
    if value.upper().startswith("WIFI:"):
        return "wifi"
    return "text"


def ocr_image(image: np.ndarray) -> str:
    """Run local OCR, retrying an empty result with the normalized image."""
    try:
        from rapidocr_onnxruntime import RapidOCR
        ocr = RapidOCR()
    except (ImportError, RuntimeError, OSError) as exc:
        raise OCRUnavailableError(
            "OCR engine is not installed or not available; install rapidocr_onnxruntime"
        ) from exc

    try:
        original_result, _ = ocr(image)
        processed_result, _ = ocr(preprocess_image(image))
    except (cv2.error, OSError, RuntimeError, ValueError) as exc:
        raise OCRProcessingError("OCR could not process this image.") from exc

    result = (
        processed_result
        if _ocr_result_quality(processed_result) > _ocr_result_quality(original_result)
        else original_result
    )
    return _ocr_result_text(result)


def _ocr_result_text(result: list | tuple | None) -> str:
    if not result:
        return ""
    return "\n".join(
        item[1] for item in result
        if isinstance(item, (list, tuple)) and len(item) > 1 and isinstance(item[1], str) and item[1]
    ).strip()


def _ocr_result_quality(result: list | tuple | None) -> float:
    if not result:
        return -1.0

    confidences = []
    for item in result:
        if isinstance(item, (list, tuple)) and len(item) > 2:
            try:
                confidences.append(float(item[2]))
            except (TypeError, ValueError):
                continue
    if confidences:
        return sum(confidences) / len(confidences)
    return 0.0 if _ocr_result_text(result) else -1.0