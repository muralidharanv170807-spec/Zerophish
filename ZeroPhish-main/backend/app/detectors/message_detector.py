"""
PhishGuard AI — Message/Content Detector
Analyzes email/SMS/message content for phishing indicators using pattern matching.
"""

import re
from backend.app.config import (
    URGENCY_PATTERNS, ACCOUNT_SUSPENSION_PATTERNS,
    CREDENTIAL_REQUEST_PATTERNS, PASSWORD_PATTERNS,
    OTP_PATTERNS, PAYMENT_PATTERNS, FINANCIAL_PATTERNS,
    PRIZE_REWARD_PATTERNS, IMPERSONATION_PATTERNS,
)
from backend.app.detectors.url_detector import analyze_url, extract_urls


def analyze_message(message: str) -> dict:
    """Analyze message content for phishing indicators."""
    text = message.lower()
    indicators = []
    category_scores = {}

    # 1. Urgency detection
    if _match_patterns(text, URGENCY_PATTERNS):
        indicators.append("Urgency language detected")
        category_scores["urgency"] = True

    # 2. Account suspension
    if _match_patterns(text, ACCOUNT_SUSPENSION_PATTERNS):
        indicators.append("Account suspension/security threat language")
        category_scores["account_suspension"] = True

    # 3. Credential request
    if _match_patterns(text, CREDENTIAL_REQUEST_PATTERNS):
        indicators.append("Credential/identity verification request")
        category_scores["credential_request"] = True

    # 4. Password request
    if _match_patterns(text, PASSWORD_PATTERNS):
        indicators.append("Password reset/change request")
        category_scores["password_request"] = True

    # 5. OTP request
    if _match_patterns(text, OTP_PATTERNS):
        indicators.append("OTP/verification code request")
        category_scores["otp_request"] = True

    # 6. Payment request
    if _match_patterns(text, PAYMENT_PATTERNS):
        indicators.append("Payment/financial transaction request")
        category_scores["payment_request"] = True

    # 7. Financial language
    if _match_patterns(text, FINANCIAL_PATTERNS):
        indicators.append("Financial/banking language detected")
        category_scores["financial_language"] = True

    # 8. Prize/reward scam
    if _match_patterns(text, PRIZE_REWARD_PATTERNS):
        indicators.append("Prize/reward/lottery scam language")
        category_scores["prize_scam"] = True

    # 9. Impersonation
    if _match_patterns(text, IMPERSONATION_PATTERNS):
        indicators.append("Organization impersonation language")
        category_scores["impersonation"] = True

    # 10. Social engineering (combination of multiple indicators)
    se_count = sum(1 for k in ["urgency", "credential_request", "account_suspension",
                                "impersonation"] if k in category_scores)
    if se_count >= 2:
        indicators.append("Multiple social engineering tactics detected")
        category_scores["social_engineering"] = True

    # 11. Extract and analyze URLs in message
    urls = extract_urls(message)
    url_analysis_results = []
    if urls:
        for url in urls[:5]:  # Analyze up to 5 URLs
            url_result = analyze_url(url)
            url_analysis_results.append({
                "url": url,
                "indicators": url_result["indicators"],
                "indicator_score": url_result["indicator_score"],
            })
            if url_result["indicators"]:
                indicators.append(f"Suspicious link found: {url[:60]}...")

    # Compute content indicator score (0-100)
    indicator_score = min(100, len(indicators) * 12)

    return {
        "indicators": indicators,
        "indicator_count": len(indicators),
        "indicator_score": indicator_score,
        "category_scores": category_scores,
        "urls_found": urls,
        "url_analysis": url_analysis_results,
    }


def _match_patterns(text: str, patterns: list[str]) -> bool:
    """Check if text matches any of the regex patterns."""
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False
