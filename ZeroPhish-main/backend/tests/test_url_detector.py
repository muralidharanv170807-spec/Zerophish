import unittest
from unittest.mock import patch

from fastapi import HTTPException

from backend.app.api.routes import (
    MessageRequest,
    URLRequest,
    analyze_message_endpoint,
    analyze_url_endpoint,
)
from backend.app.detectors.message_detector import analyze_message
from backend.app.detectors.url_detector import analyze_url, extract_url_features
from backend.app.ml.dataset import _extract_features_from_url


class URLDetectorTests(unittest.TestCase):
    def test_rejects_malformed_and_non_web_urls(self):
        for url in ("http://[broken", "https://example.com:invalid", "javascript:alert(1)"):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    analyze_url(url)

    def test_url_endpoint_returns_client_error_for_malformed_url(self):
        with self.assertRaises(HTTPException) as raised:
            analyze_url_endpoint(URLRequest(url="http://[broken"))
        self.assertEqual(raised.exception.status_code, 422)

    def test_url_and_message_endpoints_preserve_success_response_shape(self):
        with patch("backend.app.api.routes.predictor.predict_url", return_value=0.01):
            with patch("backend.app.api.routes.save_scan", return_value=31):
                url_result = analyze_url_endpoint(URLRequest(url="https://example.com"))
        with patch("backend.app.api.routes.predictor.predict_message", return_value=0.01):
            with patch("backend.app.api.routes.save_scan", return_value=32):
                message_result = analyze_message_endpoint(
                    MessageRequest(message="The meeting is scheduled for tomorrow.")
                )

        for result, input_type, scan_id in (
            (url_result, "url", 31),
            (message_result, "message", 32),
        ):
            self.assertEqual(result.input_type, input_type)
            self.assertEqual(result.scan_id, scan_id)
            self.assertIn(result.classification, {"SAFE", "SUSPICIOUS", "PHISHING"})
            self.assertIsInstance(result.score_breakdown, dict)

    def test_detects_ipv6_host(self):
        analysis = analyze_url("https://[2001:db8::1]/login")
        self.assertIn("IP address used instead of domain name", analysis["indicators"])
        self.assertEqual(analysis["features"]["has_ip_address"], 1)

    def test_shortener_detection_uses_hostname_boundaries(self):
        microsoft = analyze_url("https://www.microsoft.com")
        deceptive_substring = analyze_url("https://notbit.ly.example.org")
        shortened = analyze_url("https://evil.bit.ly/login")

        self.assertNotIn("URL shortening service detected", microsoft["indicators"])
        self.assertNotIn("URL shortening service detected", deceptive_substring["indicators"])
        self.assertIn("URL shortening service detected", shortened["indicators"])

    def test_message_scanner_extracts_bare_domains_and_ip_urls(self):
        analysis = analyze_message("Visit login.example.org/reset or 192.0.2.10/login.")
        self.assertEqual(
            analysis["urls_found"],
            ["http://login.example.org/reset", "http://192.0.2.10/login"],
        )
        self.assertEqual(len(analysis["url_analysis"]), 2)

    def test_training_and_inference_share_url_features(self):
        url = "https://notbit.ly.example.org/account"
        self.assertEqual(_extract_features_from_url(url), extract_url_features(url))


if __name__ == "__main__":
    unittest.main()
