import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer as SklearnTfidfVectorizer
from sklearn.preprocessing import StandardScaler as SklearnStandardScaler

from backend.app.ml.train import URL_FEATURE_COLUMNS, train_message_model, train_url_model


class RecordingScaler:
    def __init__(self):
        self.scaler = SklearnStandardScaler()
        self.fit_sample_count = 0

    def fit_transform(self, values):
        self.fit_sample_count = len(values)
        return self.scaler.fit_transform(values)

    def transform(self, values):
        return self.scaler.transform(values)


class RecordingVectorizer:
    def __init__(self, **kwargs):
        self.vectorizer = SklearnTfidfVectorizer(**kwargs)
        self.fit_sample_count = 0

    def fit_transform(self, values):
        self.fit_sample_count = len(values)
        return self.vectorizer.fit_transform(values)

    def transform(self, values):
        return self.vectorizer.transform(values)


class ZeroClassifier:
    def fit(self, features, labels):
        self.feature_importances_ = np.zeros(features.shape[1])
        return self

    def predict(self, features):
        return np.zeros(features.shape[0], dtype=int)


class TrainingPipelineTests(unittest.TestCase):
    def balanced_labels(self):
        return np.array([0] * 20 + [1] * 20)

    def test_url_scaler_fits_training_partition_only_and_reports_error_rates(self):
        values = np.arange(40 * len(URL_FEATURE_COLUMNS)).reshape(40, -1)
        dataset = pd.DataFrame(values, columns=URL_FEATURE_COLUMNS)
        dataset["label"] = self.balanced_labels()
        scaler = RecordingScaler()

        with tempfile.TemporaryDirectory() as directory:
            model_path = str(Path(directory) / "url_model.joblib")
            scaler_path = str(Path(directory) / "url_scaler.joblib")
            with patch("backend.app.ml.train.generate_url_dataset", return_value=dataset):
                with patch("backend.app.ml.train.StandardScaler", return_value=scaler):
                    with patch("backend.app.ml.train.RandomForestClassifier", return_value=ZeroClassifier()):
                        with patch("backend.app.ml.train.joblib.dump"):
                            with patch("backend.app.ml.train.URL_MODEL_PATH", model_path):
                                with patch("backend.app.ml.train.URL_SCALER_PATH", scaler_path):
                                    result = train_url_model()

        self.assertEqual(scaler.fit_sample_count, result["train_samples"])
        self.assertEqual(result["test_samples"], 8)
        self.assertIn("false_positive_rate", result)
        self.assertIn("false_negative_rate", result)

    def test_message_vectorizer_fits_training_partition_only_and_reports_error_rates(self):
        dataset = pd.DataFrame({
            "message": [f"distinctiveword{i} common message" for i in range(40)],
            "label": self.balanced_labels(),
        })
        vectorizer = RecordingVectorizer()

        with tempfile.TemporaryDirectory() as directory:
            model_path = str(Path(directory) / "message_model.joblib")
            vectorizer_path = str(Path(directory) / "message_vectorizer.joblib")
            with patch("backend.app.ml.train.generate_message_dataset", return_value=dataset):
                with patch("backend.app.ml.train.TfidfVectorizer", return_value=vectorizer):
                    with patch("backend.app.ml.train.RandomForestClassifier", return_value=ZeroClassifier()):
                        with patch("backend.app.ml.train.joblib.dump"):
                            with patch("backend.app.ml.train.MESSAGE_MODEL_PATH", model_path):
                                with patch("backend.app.ml.train.MESSAGE_VECTORIZER_PATH", vectorizer_path):
                                    result = train_message_model()

        self.assertEqual(vectorizer.fit_sample_count, result["train_samples"])
        self.assertEqual(result["test_samples"], 8)
        self.assertIn("false_positive_rate", result)
        self.assertIn("false_negative_rate", result)


if __name__ == "__main__":
    unittest.main()
