"""
PhishGuard AI — Behavioral Detector
Detects behavioral threat patterns that indicate phishing intent.
Independent of content/URL pattern matching — focuses on what the message ASKS the user to DO.
"""

import re


def analyze_behavior(text: str, url_indicators: list[str] = None, content_indicators: list[str] = None) -> dict:
    """
    Analyze behavioral signals in text.
    This detector focuses on the ACTION requested, not just keywords.
    """
    lower_text = text.lower()
    indicators = []
    signals = {}

    # 1. Credential harvesting — asks user to enter/provide credentials
    cred_patterns = [
        r"(?:enter|type|provide|input|fill\s+in)\s+(?:your\s+)?(?:username|user\s+name|email|id|login)",
        r"(?:enter|type|provide|input|fill\s+in)\s+(?:your\s+)?password",
        r"(?:sign|log)\s*(?:in|on)\s+(?:to\s+)?(?:your|the)",
        r"(?:enter|type|provide|input)\s+(?:your\s+)?(?:credentials|details|information)",
    ]
    if _match_any(lower_text, cred_patterns):
        indicators.append("Requests user to enter login credentials")
        signals["credential_harvesting"] = True

    # 2. OTP harvesting — asks for one-time codes
    otp_patterns = [
        r"(?:share|send|forward|provide|enter|give)\s+(?:us\s+)?(?:your\s+)?(?:otp|verification\s+code|security\s+code|one.?time)",
        r"(?:enter|provide|share|send|give)\s+(?:your\s+)?(?:password\s+and\s+)?(?:otp|verification\s+code|security\s+code)",
        r"(?:reply|respond)\s+(?:with|back\s+with)\s+(?:the\s+)?(?:code|otp|pin)",
    ]
    if _match_any(lower_text, otp_patterns):
        indicators.append("Requests user to share OTP/verification code")
        signals["otp_harvesting"] = True

    # 3. Payment request — asks for money
    payment_patterns = [
        r"(?:send|transfer|wire|pay)\s+(?:us\s+)?(?:the\s+)?(?:amount|money|payment|funds|\$\d+)",
        r"(?:purchase|buy)\s+(?:gift\s+cards?|vouchers?|bitcoin|crypto)",
        r"(?:provide|enter|share)\s+(?:your\s+)?(?:credit\s+card|debit\s+card|bank\s+(?:account|details))",
    ]
    if _match_any(lower_text, payment_patterns):
        indicators.append("Requests payment or financial information")
        signals["payment_request"] = True

    # 4. Urgency pressure — creates time pressure for action
    urgency_patterns = [
        r"(?:within|in)\s+\d+\s+(?:hours?|minutes?|days?)\s+(?:or|otherwise|else)",
        r"(?:failure\s+to|if\s+you\s+(?:don'?t|do\s+not|fail\s+to))\s+.*(?:will\s+(?:result|lead)|account\s+will)",
        r"(?:immediately|right\s+now|without\s+delay)\s+(?:to\s+(?:avoid|prevent))",
    ]
    if _match_any(lower_text, urgency_patterns):
        indicators.append("Creates urgency pressure to force quick action")
        signals["urgency_pressure"] = True

    # 5. Account closure threat
    closure_patterns = [
        r"(?:account|access)\s+(?:will\s+be|shall\s+be)\s+(?:closed|terminated|deleted|permanently\s+(?:locked|disabled|suspended))",
        r"(?:lose|losing)\s+(?:access\s+to\s+)?(?:your\s+)?account",
        r"(?:permanent(?:ly)?)\s+(?:lock|disable|suspend|close|delete|terminate)",
    ]
    if _match_any(lower_text, closure_patterns):
        indicators.append("Threatens account closure or permanent action")
        signals["account_closure_threat"] = True

    # 6. Unknown/suspicious link click request
    link_patterns = [
        r"click\s+(?:here|below|this\s+link|the\s+(?:link|button))\s+(?:to|for|now|immediately)",
        r"(?:visit|go\s+to|open|access)\s+(?:this|the\s+following)\s+(?:link|url|page|website)",
        r"(?:tap|press)\s+(?:here|below|the\s+button)",
    ]
    if _match_any(lower_text, link_patterns):
        indicators.append("Urges user to click an external link")
        signals["link_click_request"] = True

    # 7. Download request
    download_patterns = [
        r"(?:download|install|open|run)\s+(?:the\s+)?(?:attached|enclosed|following)\s+(?:file|document|attachment|app|software)",
        r"(?:see|view|open)\s+(?:the\s+)?attach(?:ed|ment)",
        r"(?:download|install)\s+(?:this|the|our)\s+(?:app|update|patch|tool)",
    ]
    if _match_any(lower_text, download_patterns):
        indicators.append("Requests user to download or open an attachment")
        signals["download_request"] = True

    # 8. Organization impersonation (behavioral level — pretending to be from an org)
    impersonation_patterns = [
        r"(?:this\s+is|we\s+are)\s+(?:from\s+)?(?:the\s+)?(?:security|support|billing|admin|compliance|fraud\s+(?:detection|prevention))\s+(?:team|department|division)",
        r"(?:on\s+behalf\s+of|representing)\s+(?:the\s+)?(?:bank|company|organization|institution)",
        r"(?:as\s+(?:a|your)\s+)?(?:bank|service\s+provider|account\s+manager|security\s+officer)",
    ]
    if _match_any(lower_text, impersonation_patterns):
        indicators.append("Impersonates an organization or authority figure")
        signals["organization_impersonation"] = True

    # Compute behavioral score
    behavioral_score = min(100, len(indicators) * 18)

    return {
        "indicators": indicators,
        "indicator_count": len(indicators),
        "behavioral_score": behavioral_score,
        "signals": signals,
    }


def _match_any(text: str, patterns: list[str]) -> bool:
    """Check if text matches any pattern."""
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False
