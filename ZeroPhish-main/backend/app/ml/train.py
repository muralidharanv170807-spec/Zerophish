"""
PhishGuard AI — ML Training Pipeline
Trains separate Random Forest models for URL and message classification.
Calculates Accuracy, Precision, Recall, F1-score, and Confusion Matrix.
"""

import os
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report, accuracy_score, precision_score,
    recall_score, f1_score, confusion_matrix
)

from backend.app.config import (
    URL_MODEL_PATH, MESSAGE_MODEL_PATH,
    URL_SCALER_PATH, MESSAGE_VECTORIZER_PATH,
)
from backend.app.ml.dataset import generate_url_dataset, generate_message_dataset


# Feature columns for URL model (must match url_detector.extract_url_features keys)
URL_FEATURE_COLUMNS = [
    "url_length", "has_https", "has_ip_address", "has_at_symbol",
    "dot_count", "hyphen_count", "subdomain_count", "path_length",
    "query_length", "has_suspicious_tld", "suspicious_keyword_count",
    "is_shortened", "has_brand_impersonation", "digit_count_in_domain",
    "has_double_slash_redirect", "special_char_count",
]


def train_url_model() -> dict:
    """Train a Random Forest classifier for URL phishing detection."""
    print("\n" + "=" * 60)
    print("Training URL Phishing Detection Model")
    print("=" * 60)

    # Load or generate dataset
    dataset_path = "data/url_dataset.csv"
    df = generate_url_dataset(dataset_path)

    X = df[URL_FEATURE_COLUMNS].values
    y = df["label"].values

    # Split before fitting preprocessing to keep test data out of training state.
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    # Train Random Forest
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        min_samples_split=4,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    false_positive_rate, false_negative_rate = _error_rates(cm)
    report = classification_report(
        y_test, y_pred, target_names=["Legitimate", "Phishing"], zero_division=0
    )

    n_phishing = int(np.sum(y))
    n_legitimate = int(len(y) - n_phishing)

    print(f"\n[ML] Dataset Stats: Total={len(df)}, Legitimate={n_legitimate}, Phishing={n_phishing}")
    print(f"[ML] Train samples: {len(y_train)}, Test samples: {len(y_test)}")
    print(f"\n[ML] Evaluation Metrics:")
    print(f"  Accuracy:  {accuracy:.4f}")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall:    {recall:.4f}")
    print(f"  F1-Score:  {f1:.4f}")
    print(f"  False-positive rate: {false_positive_rate:.4f}")
    print(f"  False-negative rate: {false_negative_rate:.4f}")
    print(f"\n[ML] Confusion Matrix:\n{cm}")
    print(f"\n[ML] Classification Report:\n{report}")

    # Feature importance
    importances = dict(zip(URL_FEATURE_COLUMNS, model.feature_importances_))
    sorted_imp = sorted(importances.items(), key=lambda x: x[1], reverse=True)
    print("[ML] Top Feature Importances:")
    for feat, imp in sorted_imp[:5]:
        print(f"  {feat}: {imp:.4f}")

    # Save model and scaler
    os.makedirs(os.path.dirname(URL_MODEL_PATH), exist_ok=True)
    joblib.dump(model, URL_MODEL_PATH)
    joblib.dump(scaler, URL_SCALER_PATH)
    print(f"\n[ML] URL model saved to {URL_MODEL_PATH}")
    print(f"[ML] URL scaler saved to {URL_SCALER_PATH}")

    return {
        "model_type": "Random Forest (URL)",
        "dataset_size": len(df),
        "total_samples": len(df),
        "legitimate_samples": n_legitimate,
        "phishing_samples": n_phishing,
        "train_samples": len(y_train),
        "test_samples": len(y_test),
        "test_accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(false_positive_rate, 4),
        "false_negative_rate": round(false_negative_rate, 4),
        "confusion_matrix": cm.tolist(),
    }


def train_message_model() -> dict:
    """Train a TF-IDF + Random Forest classifier for message phishing detection."""
    print("\n" + "=" * 60)
    print("Training Message Phishing Detection Model")
    print("=" * 60)

    # Load or generate dataset
    dataset_path = "data/message_dataset.csv"
    df = generate_message_dataset(dataset_path)

    texts = df["message"].astype(str).values
    y = df["label"].values
    X_train_text, X_test_text, y_train, y_test = train_test_split(
        texts, y, test_size=0.2, random_state=42, stratify=y
    )

    vectorizer = TfidfVectorizer(
        max_features=1000,
        stop_words="english",
        ngram_range=(1, 2),
        min_df=1,
        max_df=0.95,
    )
    X_train = vectorizer.fit_transform(X_train_text)
    X_test = vectorizer.transform(X_test_text)

    # Train Random Forest
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        min_samples_split=3,
        min_samples_leaf=1,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    false_positive_rate, false_negative_rate = _error_rates(cm)
    report = classification_report(
        y_test, y_pred, target_names=["Legitimate", "Phishing"], zero_division=0
    )

    n_phishing = int(np.sum(y))
    n_legitimate = int(len(y) - n_phishing)

    print(f"\n[ML] Dataset Stats: Total={len(df)}, Legitimate={n_legitimate}, Phishing={n_phishing}")
    print(f"[ML] Train samples: {X_train.shape[0]}, Test samples: {X_test.shape[0]}")
    print(f"\n[ML] Evaluation Metrics:")
    print(f"  Accuracy:  {accuracy:.4f}")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall:    {recall:.4f}")
    print(f"  F1-Score:  {f1:.4f}")
    print(f"  False-positive rate: {false_positive_rate:.4f}")
    print(f"  False-negative rate: {false_negative_rate:.4f}")
    print(f"\n[ML] Confusion Matrix:\n{cm}")
    print(f"\n[ML] Classification Report:\n{report}")

    # Save model and vectorizer
    os.makedirs(os.path.dirname(MESSAGE_MODEL_PATH), exist_ok=True)
    joblib.dump(model, MESSAGE_MODEL_PATH)
    joblib.dump(vectorizer, MESSAGE_VECTORIZER_PATH)
    print(f"\n[ML] Message model saved to {MESSAGE_MODEL_PATH}")
    print(f"[ML] Message vectorizer saved to {MESSAGE_VECTORIZER_PATH}")

    return {
        "model_type": "TF-IDF + Random Forest (Message)",
        "dataset_size": len(df),
        "total_samples": len(df),
        "legitimate_samples": n_legitimate,
        "phishing_samples": n_phishing,
        "train_samples": X_train.shape[0],
        "test_samples": X_test.shape[0],
        "test_accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(false_positive_rate, 4),
        "false_negative_rate": round(false_negative_rate, 4),
        "confusion_matrix": cm.tolist(),
    }


def train_all():
    """Train both URL and message models."""
    print("\n" + "#" * 60)
    print("PhishGuard AI — ML Training Pipeline")
    print("#" * 60)

    url_result = train_url_model()
    message_result = train_message_model()

    print("\n" + "=" * 60)
    print("Training Complete!")
    print("=" * 60)
    print(f"\nURL Model: accuracy={url_result['test_accuracy']}, precision={url_result['precision']}, recall={url_result['recall']}, f1={url_result['f1_score']}, samples={url_result['dataset_size']}")
    print(f"Message Model: accuracy={message_result['test_accuracy']}, precision={message_result['precision']}, recall={message_result['recall']}, f1={message_result['f1_score']}, samples={message_result['dataset_size']}")
    print(f"\nModels saved. Backend will load these automatically on startup.")

    return {"url": url_result, "message": message_result}


def _error_rates(confusion_matrix_values: np.ndarray) -> tuple[float, float]:
    """Return false-positive and false-negative rates for labels 0 and 1."""
    true_negative, false_positive, false_negative, true_positive = confusion_matrix_values.ravel()
    false_positive_rate = (
        false_positive / (false_positive + true_negative)
        if false_positive + true_negative else 0.0
    )
    false_negative_rate = (
        false_negative / (false_negative + true_positive)
        if false_negative + true_positive else 0.0
    )
    return false_positive_rate, false_negative_rate


if __name__ == "__main__":
    train_all()
