"""
PhishGuard AI — ML Predictor
Loads trained models and produces phishing probability predictions.
Every ML probability returned by this module comes from the actual loaded model.
"""

import os
import numpy as np
import joblib
from backend.app.config import (
    URL_MODEL_PATH, MESSAGE_MODEL_PATH,
    URL_SCALER_PATH, MESSAGE_VECTORIZER_PATH,
)
from backend.app.ml.train import URL_FEATURE_COLUMNS


class PhishingPredictor:
    """Loads and manages ML models for phishing prediction."""

    def __init__(self):
        self.url_model = None
        self.url_scaler = None
        self.message_model = None
        self.message_vectorizer = None
        self.url_model_loaded = False
        self.message_model_loaded = False

    def load_models(self):
        """Load trained models from disk. Call on application startup."""
        # Load URL model
        if os.path.exists(URL_MODEL_PATH) and os.path.exists(URL_SCALER_PATH):
            try:
                self.url_model = joblib.load(URL_MODEL_PATH)
                self.url_scaler = joblib.load(URL_SCALER_PATH)
                self.url_model_loaded = True
                print(f"[ML] URL model loaded from {URL_MODEL_PATH}")
            except Exception as e:
                print(f"[ML] WARNING: Failed to load URL model: {e}")
                self.url_model_loaded = False
        else:
            print(f"[ML] WARNING: URL model not found at {URL_MODEL_PATH}")
            print(f"[ML] Run 'python -m backend.app.ml.train' to train the model.")
            self.url_model_loaded = False

        # Load message model
        if os.path.exists(MESSAGE_MODEL_PATH) and os.path.exists(MESSAGE_VECTORIZER_PATH):
            try:
                self.message_model = joblib.load(MESSAGE_MODEL_PATH)
                self.message_vectorizer = joblib.load(MESSAGE_VECTORIZER_PATH)
                self.message_model_loaded = True
                print(f"[ML] Message model loaded from {MESSAGE_MODEL_PATH}")
            except Exception as e:
                print(f"[ML] WARNING: Failed to load message model: {e}")
                self.message_model_loaded = False
        else:
            print(f"[ML] WARNING: Message model not found at {MESSAGE_MODEL_PATH}")
            print(f"[ML] Run 'python -m backend.app.ml.train' to train the model.")
            self.message_model_loaded = False

    def predict_url(self, features: dict) -> float:
        """
        Predict phishing probability for a URL based on its extracted features.
        Returns a probability between 0.0 and 1.0.
        """
        if not self.url_model_loaded:
            # Fallback: rule-based estimation when model is not available
            print("[ML] WARNING: URL model not loaded, using rule-based fallback")
            return self._rule_based_url_score(features)

        # Build feature vector in the correct order
        feature_vector = np.array([[features.get(col, 0) for col in URL_FEATURE_COLUMNS]])

        # Scale features
        feature_vector_scaled = self.url_scaler.transform(feature_vector)

        # Get phishing probability from the actual model
        probabilities = self.url_model.predict_proba(feature_vector_scaled)
        phishing_probability = float(probabilities[0][1])  # Probability of class 1 (phishing)

        return phishing_probability

    def predict_message(self, message: str) -> float:
        """
        Predict phishing probability for a message using TF-IDF + Random Forest.
        Returns a probability between 0.0 and 1.0.
        """
        if not self.message_model_loaded:
            # Fallback: rule-based estimation when model is not available
            print("[ML] WARNING: Message model not loaded, using rule-based fallback")
            return self._rule_based_message_score(message)

        # Vectorize the message using the trained TF-IDF vectorizer
        message_vector = self.message_vectorizer.transform([message])

        # Get phishing probability from the actual model
        probabilities = self.message_model.predict_proba(message_vector)
        phishing_probability = float(probabilities[0][1])  # Probability of class 1 (phishing)

        return phishing_probability

    def get_status(self) -> dict:
        """Get the current status of loaded models."""
        return {
            "url_model_loaded": self.url_model_loaded,
            "message_model_loaded": self.message_model_loaded,
        }

    @staticmethod
    def _rule_based_url_score(features: dict) -> float:
        """Simple rule-based fallback when ML model is unavailable."""
        score = 0.0
        if not features.get("has_https", 0):
            score += 0.15
        if features.get("has_ip_address", 0):
            score += 0.2
        if features.get("has_at_symbol", 0):
            score += 0.15
        if features.get("has_suspicious_tld", 0):
            score += 0.15
        if features.get("suspicious_keyword_count", 0) > 0:
            score += min(0.15, features["suspicious_keyword_count"] * 0.05)
        if features.get("is_shortened", 0):
            score += 0.1
        if features.get("has_brand_impersonation", 0):
            score += 0.2
        if features.get("url_length", 0) > 75:
            score += 0.1
        return min(1.0, score)

    @staticmethod
    def _rule_based_message_score(message: str) -> float:
        """Simple rule-based fallback when ML model is unavailable."""
        lower = message.lower()
        score = 0.0
        phishing_keywords = [
            "urgent", "suspended", "verify", "password", "click here",
            "otp", "account", "immediately", "credential", "confirm",
            "prize", "won", "bank", "login", "expire",
        ]
        for kw in phishing_keywords:
            if kw in lower:
                score += 0.08
        return min(1.0, score)


# Global predictor instance
predictor = PhishingPredictor()
