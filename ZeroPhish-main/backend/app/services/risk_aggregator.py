"""
PhishGuard AI — Risk Aggregator
Centralized risk scoring that combines ML probability, URL indicators,
content indicators, and behavioral indicators into a final risk assessment.

Uses adaptive weight profiles (URL mode vs message mode) to avoid
penalizing scans where certain channels are not applicable.
Applies a corroboration boost when multiple independent channels
converge on high-risk signals.
"""

from math import exp

from backend.app.config import (
    RISK_THRESHOLDS,
    RISK_WEIGHTS_URL,
    RISK_WEIGHTS_MESSAGE,
    CORROBORATION_BOOST,
    CORROBORATION_THRESHOLD,
    SCREENSHOT_BEHAVIORAL_SATURATION,
    SCREENSHOT_CONTENT_SATURATION,
    SCREENSHOT_WEIGHTS_NO_URL,
    SCREENSHOT_WEIGHTS_WITH_URL,
)


def aggregate_screenshot_risk(
    message_probability: float,
    url_probability: float | None,
    content_indicator_score: float,
    behavioral_score: float,
    all_indicators: list[str] | None = None,
    behavioral_indicator_count: int = 0,
    url_indicator_score: float = 0,
) -> dict:
    """Fuse screenshot evidence without counting OCR URLs twice.

    Indicator scores are converted to evidence probabilities with a saturating
    curve. This preserves model probabilities as diagnostics while allowing
    corroborated detector evidence to drive the final decision.
    """
    indicators = all_indicators or []
    content_evidence = 1 - exp(-max(content_indicator_score, 0) / SCREENSHOT_CONTENT_SATURATION)
    behavioral_evidence = 1 - exp(-max(behavioral_score, 0) / SCREENSHOT_BEHAVIORAL_SATURATION)
    url_indicator_evidence = 1 - exp(-max(url_indicator_score, 0) / SCREENSHOT_CONTENT_SATURATION)
    has_url = url_probability is not None
    weights = SCREENSHOT_WEIGHTS_WITH_URL if has_url else SCREENSHOT_WEIGHTS_NO_URL

    components = {
        "ml_component": message_probability * weights["message_probability"] * 100,
        "url_component": (url_probability or 0) * weights.get("url_probability", 0) * 100,
        "url_indicator_component": url_indicator_evidence * weights.get("url_indicator_evidence", 0) * 100,
        "content_component": content_evidence * weights["content_evidence"] * 100,
        "behavioral_component": behavioral_evidence * weights["behavioral_evidence"] * 100,
    }
    risk_score = max(0, min(100, round(sum(components.values()))))
    classification = _classify(risk_score)
    explanation = _generate_explanation(
        classification,
        risk_score,
        message_probability,
        0,
        content_indicator_score,
        behavioral_score,
        indicators,
    )
    return {
        "classification": classification,
        "risk_score": risk_score,
        "ml_probability": round(message_probability, 4),
        "indicators": indicators,
        "explanation": explanation,
        "recommendations": _generate_recommendations(classification, indicators),
        "score_breakdown": {key: round(value, 2) for key, value in components.items()},
        "diagnostics": {
            "message_model_probability": round(message_probability, 4),
            "url_model_probability": round(url_probability, 4) if url_probability is not None else None,
            "url_indicator_evidence": round(url_indicator_evidence, 4),
            "content_evidence": round(content_evidence, 4),
            "behavioral_evidence": round(behavioral_evidence, 4),
            "behavioral_indicator_count": behavioral_indicator_count,
        },
    }


def aggregate_risk(
    ml_probability: float,
    url_indicator_score: float = 0,
    content_indicator_score: float = 0,
    behavioral_score: float = 0,
    all_indicators: list[str] = None,
    analysis_mode: str = "url",
) -> dict:
    """
    Combine all analysis signals into a final risk assessment.

    Args:
        ml_probability: ML model phishing probability (0.0-1.0)
        url_indicator_score: URL-based indicator score (0-100)
        content_indicator_score: Content-based indicator score (0-100)
        behavioral_score: Behavioral analysis score (0-100)
        all_indicators: Combined list of all detected indicators
        analysis_mode: "url" or "message" — selects the weight profile

    Returns:
        Complete risk assessment with score, classification, and explanation.
    """
    if all_indicators is None:
        all_indicators = []

    # Select weight profile based on analysis mode
    if analysis_mode == "message":
        weights = RISK_WEIGHTS_MESSAGE
    else:
        weights = RISK_WEIGHTS_URL

    # Scale ML probability to 0-100
    ml_score_100 = ml_probability * 100

    # Compute weighted components
    ml_component = ml_score_100 * weights["ml_probability"]
    url_component = url_indicator_score * weights["url_indicators"]

    if analysis_mode == "message":
        content_component = content_indicator_score * weights["content_indicators"]
    else:
        # URL mode: no content channel — weight is already excluded from profile
        content_component = 0.0

    behavioral_component = behavioral_score * weights["behavioral_indicators"]

    # Raw weighted sum (before corroboration)
    raw_score = ml_component + url_component + content_component + behavioral_component

    # --- Corroboration boost ---
    # Count how many independent channels report scores above the threshold.
    # Each additional high-risk channel beyond the first boosts the score.
    channel_scores = [ml_score_100, url_indicator_score, behavioral_score]
    if analysis_mode == "message":
        channel_scores.append(content_indicator_score)

    high_risk_channels = sum(1 for s in channel_scores if s > CORROBORATION_THRESHOLD)
    boost_multiplier = 1.0 + max(0, high_risk_channels - 1) * CORROBORATION_BOOST

    boosted_score = raw_score * boost_multiplier

    # Clamp to 0-100
    risk_score = max(0, min(100, round(boosted_score)))

    # Compute breakdown components (boosted), scaled proportionally if clamped
    boosted_ml = ml_component * boost_multiplier
    boosted_url = url_component * boost_multiplier
    boosted_content = content_component * boost_multiplier
    boosted_behavioral = behavioral_component * boost_multiplier

    # If boosted_score exceeds 100, proportionally scale components so they sum to risk_score
    if boosted_score > 100 and boosted_score > 0:
        scale_factor = 100.0 / boosted_score
        boosted_ml *= scale_factor
        boosted_url *= scale_factor
        boosted_content *= scale_factor
        boosted_behavioral *= scale_factor

    # Classification
    classification = _classify(risk_score)

    # Generate explanation
    explanation = _generate_explanation(
        classification, risk_score, ml_probability,
        url_indicator_score, content_indicator_score, behavioral_score,
        all_indicators
    )

    # Generate recommendations
    recommendations = _generate_recommendations(classification, all_indicators)

    return {
        "classification": classification,
        "risk_score": risk_score,
        "ml_probability": round(ml_probability, 4),
        "indicators": all_indicators,
        "explanation": explanation,
        "recommendations": recommendations,
        "score_breakdown": {
            "ml_component": round(boosted_ml, 2),
            "url_component": round(boosted_url, 2),
            "content_component": round(boosted_content, 2),
            "behavioral_component": round(boosted_behavioral, 2),
        }
    }


def _classify(score: int) -> str:
    """Classify risk score into SAFE, SUSPICIOUS, or PHISHING."""
    if score <= RISK_THRESHOLDS["safe_max"]:
        return "SAFE"
    elif score <= RISK_THRESHOLDS["suspicious_max"]:
        return "SUSPICIOUS"
    else:
        return "PHISHING"


def _generate_explanation(
    classification: str, risk_score: int, ml_probability: float,
    url_score: float, content_score: float, behavioral_score: float,
    indicators: list[str]
) -> str:
    """Generate a human-readable explanation of the risk assessment."""
    parts = []

    if classification == "PHISHING":
        parts.append(f"This input has been classified as PHISHING with a risk score of {risk_score}/100.")
        parts.append("Multiple strong indicators of phishing activity were detected.")
    elif classification == "SUSPICIOUS":
        parts.append(f"This input has been classified as SUSPICIOUS with a risk score of {risk_score}/100.")
        parts.append("Some indicators of potentially malicious activity were found.")
    else:
        parts.append(f"This input has been classified as SAFE with a risk score of {risk_score}/100.")
        parts.append("No significant phishing indicators were detected.")

    if ml_probability > 0.5:
        parts.append(f"The ML model assigned a {ml_probability:.0%} phishing probability.")

    if indicators:
        parts.append(f"{len(indicators)} threat indicator(s) were identified.")

    return " ".join(parts)


def _generate_recommendations(classification: str, indicators: list[str]) -> list[str]:
    """Generate actionable recommendations based on the classification and indicators."""
    recommendations = []
    indicator_text = " ".join(indicators).lower()

    if classification == "PHISHING":
        recommendations.append("Do not click any links in this message")
        recommendations.append("Do not provide any personal information")
        recommendations.append("Do not download any attachments")

        if "credential" in indicator_text or "login" in indicator_text or "password" in indicator_text:
            recommendations.append("Do not enter your username or password")

        if "otp" in indicator_text or "verification code" in indicator_text:
            recommendations.append("Do not share any OTP or verification codes")

        if "payment" in indicator_text or "financial" in indicator_text or "bank" in indicator_text:
            recommendations.append("Do not make any payments or share financial details")

        if "brand" in indicator_text or "impersonation" in indicator_text:
            recommendations.append("Verify through the organization's official website directly")

        recommendations.append("Report this message as phishing")
        recommendations.append("Block the sender")

    elif classification == "SUSPICIOUS":
        recommendations.append("Exercise caution before clicking any links")
        recommendations.append("Verify the sender's identity independently")
        recommendations.append("Do not provide sensitive information until verified")
        recommendations.append("Contact the organization through official channels to confirm")

    else:
        recommendations.append("This input appears safe based on our analysis")
        recommendations.append("Always stay vigilant for phishing attempts")
        recommendations.append("When in doubt, verify through official channels")

    return recommendations
