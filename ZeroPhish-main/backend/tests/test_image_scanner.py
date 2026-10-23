import sys
from io import BytesIO
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import numpy as np
from PIL import Image
from fastapi import HTTPException, UploadFile
from pydantic import ValidationError
from starlette.datastructures import Headers

from backend.app.api.routes import (
    MessageRequest,
    _read_bounded_upload,
    analyze_qr_endpoint,
    analyze_screenshot_endpoint,
)
from backend.app.services.image_scanner import (
    MAX_IMAGE_BYTES,
    MAX_IMAGE_PIXELS,
    OCRProcessingError,
    classify_payload,
    decode_image,
    extract_urls,
    ocr_image,
    validate_upload,
)
from backend.app.detectors.behavioral_detector import analyze_behavior
from backend.app.detectors.message_detector import analyze_message
from backend.app.detectors.url_detector import analyze_url
from backend.app.ml.predictor import predictor
from backend.app.services.risk_aggregator import aggregate_screenshot_risk


class ImageScannerTests(unittest.TestCase):
    def test_payload_types(self):
        self.assertEqual(classify_payload("https://example.com/login"), "url")
        self.assertEqual(classify_payload("mailto:help@example.com"), "email")
        self.assertEqual(classify_payload("WIFI:T:WPA;S:demo;P:password;;"), "wifi")
        self.assertEqual(classify_payload("Meeting room 4"), "text")

    def test_url_extraction_normalizes_www_and_deduplicates(self):
        text = "Visit https://example.com/login. Or www.example.org/help; https://example.com/login"
        self.assertEqual(
            extract_urls(text),
            ["https://example.com/login", "http://www.example.org/help"],
        )

    def test_url_extraction_handles_bare_subdomains_and_ipv4(self):
        self.assertEqual(
            extract_urls("Visit login.example.org/reset or 192.0.2.10/login."),
            ["http://login.example.org/reset", "http://192.0.2.10/login"],
        )

    def test_upload_validation(self):
        validate_upload("image/png", b"valid")
        with self.assertRaises(ValueError):
            validate_upload("text/plain", b"not an image")
        with self.assertRaises(ValueError):
            validate_upload("image/png", b"x" * (10 * 1024 * 1024 + 1))

    @staticmethod
    def make_png(width, height):
        image = Image.new("1", (width, height), 1)
        contents = BytesIO()
        image.save(contents, format="PNG")
        return contents.getvalue()

    def test_image_pixel_limit_is_checked_before_full_decode(self):
        cases = [
            (4999, 5000, True),
            (5000, 5000, True),
            (5001, 5000, False),
        ]
        for width, height, accepted in cases:
            with self.subTest(width=width, height=height):
                contents = self.make_png(width, height)
                with patch(
                    "backend.app.services.image_scanner.cv2.imdecode",
                    return_value=np.zeros((1, 1, 3), dtype=np.uint8),
                ) as imdecode:
                    if accepted:
                        decode_image(contents)
                        imdecode.assert_called_once()
                    else:
                        with self.assertRaisesRegex(ValueError, "25 megapixels"):
                            decode_image(contents)
                        imdecode.assert_not_called()

        self.assertEqual(5000 * 5000, MAX_IMAGE_PIXELS)

    def test_invalid_image_header_returns_readable_validation_error(self):
        with self.assertRaisesRegex(ValueError, "Invalid image file"):
            decode_image(b"not an image")

    def test_message_length_limit_below_at_and_above_boundary(self):
        self.assertEqual(
            MessageRequest.model_json_schema()["properties"]["message"]["maxLength"],
            10_000,
        )
        for length in (9_999, 10_000):
            with self.subTest(length=length):
                request = MessageRequest(message="x" * length)
                self.assertEqual(len(request.message), length)

        with self.assertRaises(ValidationError) as raised:
            MessageRequest(message="x" * 10_001)
        self.assertEqual(raised.exception.errors()[0]["type"], "string_too_long")
        self.assertEqual(raised.exception.errors()[0]["ctx"]["max_length"], 10_000)
        self.assertIn("10000", raised.exception.errors()[0]["msg"])

    def test_ocr_retries_with_preprocessed_image_when_original_has_no_text(self):
        class FakeOCR:
            def __init__(self):
                self.calls = 0

            def __call__(self, image):
                self.calls += 1
                if self.calls == 1:
                    return [], None
                return [(None, "Recognized text")], None

        fake_ocr = FakeOCR()
        engine_module = SimpleNamespace(RapidOCR=lambda: fake_ocr)
        image = np.zeros((8, 8, 3), dtype=np.uint8)
        with patch.dict(sys.modules, {"rapidocr_onnxruntime": engine_module}):
            with patch(
                "backend.app.services.image_scanner.preprocess_image",
                return_value=np.zeros((8, 8), dtype=np.uint8),
            ) as preprocess:
                self.assertEqual(ocr_image(image), "Recognized text")
        preprocess.assert_called_once_with(image)
        self.assertEqual(fake_ocr.calls, 2)

    def test_ocr_preprocessing_failure_is_reported(self):
        class EmptyOCR:
            def __call__(self, image):
                return [], None

        engine_module = SimpleNamespace(RapidOCR=EmptyOCR)
        image = np.zeros((8, 8, 3), dtype=np.uint8)
        with patch.dict(sys.modules, {"rapidocr_onnxruntime": engine_module}):
            with patch(
                "backend.app.services.image_scanner.preprocess_image",
                side_effect=ValueError("invalid image dimensions"),
            ):
                with self.assertRaises(OCRProcessingError):
                    ocr_image(image)

    def test_ocr_prefers_the_variant_with_higher_recognition_confidence(self):
        class ComparingOCR:
            def __init__(self):
                self.calls = 0

            def __call__(self, image):
                self.calls += 1
                if self.calls == 1:
                    return [(None, "lerify your", "0.6")], None
                return [(None, "Verify your account", "0.9")], None

        fake_ocr = ComparingOCR()
        engine_module = SimpleNamespace(RapidOCR=lambda: fake_ocr)
        image = np.zeros((8, 8, 3), dtype=np.uint8)
        with patch.dict(sys.modules, {"rapidocr_onnxruntime": engine_module}):
            with patch(
                "backend.app.services.image_scanner.preprocess_image",
                return_value=np.zeros((8, 8), dtype=np.uint8),
            ):
                self.assertEqual(ocr_image(image), "Verify your account")

    def test_screenshot_fusion_uses_independent_evidence(self):
        safe = "Hello, the meeting is tomorrow at 10 AM."
        phishing = "Verify your account immediately. Enter your password and OTP."
        predictor.load_models()
        safe_content = analyze_message(safe)
        safe_behavior = analyze_behavior(safe)
        phishing_content = analyze_message(phishing)
        phishing_behavior = analyze_behavior(phishing)
        safe_result = aggregate_screenshot_risk(
            predictor.predict_message(safe), None, safe_content["indicator_score"],
            safe_behavior["behavioral_score"], all_indicators=safe_content["indicators"],
            behavioral_indicator_count=safe_behavior["indicator_count"],
        )
        phishing_result = aggregate_screenshot_risk(
            predictor.predict_message(phishing), None, phishing_content["indicator_score"],
            phishing_behavior["behavioral_score"],
            all_indicators=phishing_content["indicators"] + phishing_behavior["indicators"],
            behavioral_indicator_count=phishing_behavior["indicator_count"],
        )
        self.assertEqual(safe_result["classification"], "SAFE")
        self.assertEqual(phishing_result["classification"], "PHISHING")
        self.assertGreater(phishing_result["risk_score"], safe_result["risk_score"])

    def test_screenshot_fusion_uses_url_model_and_url_indicators(self):
        url = "http://secure-bank-login.tk/verify"
        predictor.load_models()
        analysis = analyze_message(url)
        url_analysis = analyze_url(url)
        result = aggregate_screenshot_risk(
            predictor.predict_message(url),
            predictor.predict_url(url_analysis["features"]),
            analysis["indicator_score"],
            analyze_behavior(url)["behavioral_score"],
            all_indicators=url_analysis["indicators"],
            url_indicator_score=url_analysis["indicator_score"],
        )
        self.assertEqual(result["classification"], "PHISHING")
        self.assertGreaterEqual(result["diagnostics"]["url_model_probability"], 0.9)

class ImageRouteTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def make_upload(contents=b"image"):
        return UploadFile(
            filename="sample.png",
            file=BytesIO(contents),
            headers=Headers({"content-type": "image/png"}),
        )

    async def test_upload_read_is_bounded_before_validation(self):
        upload = self.make_upload(b"x" * (MAX_IMAGE_BYTES + 50))
        with self.assertRaises(ValueError):
            await _read_bounded_upload(upload)
        self.assertEqual(upload.file.tell(), MAX_IMAGE_BYTES + 1)

    async def test_oversized_image_dimensions_are_rejected_by_qr_route(self):
        contents = ImageScannerTests.make_png(5001, 5000)
        with self.assertRaises(HTTPException) as raised:
            await analyze_qr_endpoint(self.make_upload(contents))
        self.assertEqual(raised.exception.status_code, 400)
        self.assertIn("25 megapixels", raised.exception.detail)

    async def test_oversized_image_dimensions_are_rejected_by_screenshot_route(self):
        contents = ImageScannerTests.make_png(5001, 5000)
        with self.assertRaises(HTTPException) as raised:
            await analyze_screenshot_endpoint(self.make_upload(contents))
        self.assertEqual(raised.exception.status_code, 400)
        self.assertIn("25 megapixels", raised.exception.detail["error"])

    async def test_undecodable_qr_returns_an_error_instead_of_safe_result(self):
        upload = self.make_upload()
        with patch("backend.app.api.routes.decode_image", return_value=np.zeros((2, 2, 3))):
            with patch("backend.app.api.routes.decode_qr", return_value=(False, None)):
                with self.assertRaises(HTTPException) as raised:
                    await analyze_qr_endpoint(upload)
        self.assertEqual(raised.exception.status_code, 422)
        self.assertEqual(raised.exception.detail["stage"], "qr")

    async def test_decoded_qr_preserves_success_response_fields(self):
        upload = self.make_upload()
        payload = "http://secure-bank-login.tk/verify"
        with patch("backend.app.api.routes.decode_image", return_value=np.zeros((2, 2, 3))):
            with patch("backend.app.api.routes.decode_qr", return_value=(True, payload)):
                with patch("backend.app.api.routes.predictor.predict_url", return_value=0.95):
                    with patch("backend.app.api.routes.save_scan", return_value=17):
                        result = await analyze_qr_endpoint(upload)

        self.assertEqual(result.input_type, "qr")
        self.assertEqual(result.scan_id, 17)
        self.assertTrue(result.decoded)
        self.assertEqual(result.payload, payload)
        self.assertEqual(result.extracted_urls, [payload])

    async def test_screenshot_success_preserves_existing_response_fields(self):
        upload = self.make_upload()
        with patch("backend.app.api.routes.decode_image", return_value=np.zeros((2, 2, 3))):
            with patch("backend.app.api.routes.decode_qr", return_value=(False, None)):
                with patch("backend.app.api.routes.ocr_image", return_value="Verify your account"):
                    with patch("backend.app.api.routes.predictor.predict_message", return_value=0.05):
                        with patch("backend.app.api.routes.save_scan", return_value=23):
                            result = await analyze_screenshot_endpoint(upload)

        self.assertEqual(result.input_type, "screenshot")
        self.assertEqual(result.scan_type, "screenshot")
        self.assertEqual(result.scan_id, 23)
        self.assertTrue(result.ocr_detected)
        self.assertEqual(result.extracted_text, "Verify your account")
        self.assertEqual(result.extracted_urls, [])


if __name__ == "__main__":
    unittest.main()