"""
PhishGuard AI — Configuration
Centralized configuration for risk thresholds, weights, and application settings.
"""

# --- Risk Classification Thresholds ---
RISK_THRESHOLDS = {
    "safe_max": 30,        # 0-30 = SAFE
    "suspicious_max": 60,  # 31-60 = SUSPICIOUS
    # 61-100 = PHISHING
}

# --- Risk Aggregation Weights ---
# Adaptive weight profiles: different modes use different weight distributions
# so that unused channels don't waste scoring budget.

# Weights for URL-only analysis (no content analysis channel)
RISK_WEIGHTS_URL = {
    "ml_probability": 0.55,
    "url_indicators": 0.30,
    "behavioral_indicators": 0.15,
}

# Weights for message analysis (all four channels active)
RISK_WEIGHTS_MESSAGE = {
    "ml_probability": 0.40,
    "url_indicators": 0.20,
    "content_indicators": 0.25,
    "behavioral_indicators": 0.15,
}

# Screenshot fusion weights. Rule evidence uses a saturating transform so
# several independent phishing indicators remain meaningful when the legacy
# text model is under-confident, without adding a fixed score bonus.
SCREENSHOT_WEIGHTS_NO_URL = {
    "message_probability": 0.18,
    "content_evidence": 0.57,
    "behavioral_evidence": 0.25,
}
SCREENSHOT_WEIGHTS_WITH_URL = {
    "message_probability": 0.10,
    "url_probability": 0.35,
    "url_indicator_evidence": 0.30,
    "content_evidence": 0.05,
    "behavioral_evidence": 0.20,
}
SCREENSHOT_CONTENT_SATURATION = 18.0
SCREENSHOT_BEHAVIORAL_SATURATION = 36.0

# Corroboration boost: when multiple independent detection channels report
# high risk, the final score is boosted to reflect convergent evidence.
# Each high-risk channel beyond the first adds CORROBORATION_BOOST to a multiplier.
CORROBORATION_BOOST = 0.10

# A channel must score above this threshold (on a 0-100 scale) to count
# as "high risk" for corroboration purposes.
CORROBORATION_THRESHOLD = 40

# --- URL Analysis ---
SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz",
    ".club", ".work", ".info", ".site", ".online", ".icu", ".live",
    ".su", ".pw", ".cc", ".ws", ".bid", ".stream", ".download",
    ".racing", ".win", ".party", ".review", ".trade", ".accountant",
]

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "secure",
    "account", "update", "confirm", "bank", "paypal", "ebay", "amazon",
    "apple", "microsoft", "google", "facebook", "instagram", "netflix",
    "support", "service", "alert", "suspend", "restrict", "locked",
    "unusual", "unauthorized", "resolve", "restore", "recover",
    "wallet", "crypto", "bitcoin", "password", "credential",
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bl.ink", "lnkd.in", "db.tt", "qr.ae",
    "rebrand.ly", "shorturl.at", "cutt.ly", "rb.gy",
]

BRAND_DOMAINS = {
    "paypal": "paypal.com",
    "google": "google.com",
    "facebook": "facebook.com",
    "apple": "apple.com",
    "microsoft": "microsoft.com",
    "amazon": "amazon.com",
    "netflix": "netflix.com",
    "instagram": "instagram.com",
    "twitter": "twitter.com",
    "linkedin": "linkedin.com",
    "ebay": "ebay.com",
    "walmart": "walmart.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "bankofamerica": "bankofamerica.com",
}

# --- Message/Content Analysis ---
URGENCY_PATTERNS = [
    r"immediate(?:ly)?", r"urgent(?:ly)?", r"act\s+now", r"right\s+away",
    r"asap", r"within\s+\d+\s+hours?", r"expires?\s+(?:today|soon|immediately)",
    r"last\s+chance", r"final\s+warning", r"don'?t\s+delay",
    r"time\s+(?:is\s+)?running\s+out", r"limited\s+time",
    r"hurry", r"quick(?:ly)?", r"fast",
]

ACCOUNT_SUSPENSION_PATTERNS = [
    r"account\s+(?:has\s+been\s+)?(?:suspended|disabled|locked|restricted|compromised|closed)",
    r"suspend(?:ed|ing)?\s+(?:your\s+)?account",
    r"(?:temporary|permanent)\s+(?:suspension|ban|block)",
    r"unusual\s+(?:activity|sign.?in|login)",
    r"unauthorized\s+(?:access|activity|transaction)",
    r"security\s+(?:alert|warning|notice|breach)",
]

CREDENTIAL_REQUEST_PATTERNS = [
    r"(?:verify|confirm|update|validate)\s+(?:your\s+)?(?:identity|account|information|details|credentials)",
    r"(?:enter|provide|submit|input)\s+(?:your\s+)?(?:username|password|email|login|credentials|ssn|social\s+security)",
    r"log\s*in\s+(?:to\s+)?(?:verify|confirm|secure)",
    r"click\s+(?:here|below|the\s+link)\s+to\s+(?:verify|confirm|update|restore|unlock)",
]

PASSWORD_PATTERNS = [
    r"(?:reset|change|update|confirm)\s+(?:your\s+)?password",
    r"password\s+(?:has\s+)?(?:expired|reset|changed)",
    r"new\s+password",
    r"enter\s+(?:your\s+)?(?:current|old|new)\s+password",
]

OTP_PATTERNS = [
    r"(?:enter|provide|submit|share|send)\s+(?:your\s+)?(?:otp|one.?time\s+(?:password|code|pin)|verification\s+code)",
    r"(?:otp|code|pin)\s+(?:is|was|has\s+been)\s+sent",
    r"\b(?:otp|2fa|mfa)\b",
]

PAYMENT_PATTERNS = [
    r"(?:make|send|transfer|wire|process)\s+(?:a\s+)?payment",
    r"(?:credit|debit)\s+card\s+(?:number|details|information)",
    r"bank\s+(?:account|transfer|details|routing)",
    r"(?:pay|send|transfer)\s+\$?\d+",
    r"invoice\s+(?:attached|enclosed|due)",
    r"outstanding\s+(?:balance|payment|amount)",
]

FINANCIAL_PATTERNS = [
    r"(?:bank|financial)\s+(?:account|statement|notification)",
    r"(?:transaction|transfer|withdrawal|deposit)\s+(?:of|for)\s+\$?\d+",
    r"(?:refund|reimbursement|compensation)",
    r"tax\s+(?:refund|return|filing)",
]

PRIZE_REWARD_PATTERNS = [
    r"(?:you(?:'ve)?\s+)?(?:won|selected|chosen|winner)",
    r"(?:prize|reward|gift\s+card|bonus|lottery|jackpot|giveaway)",
    r"(?:claim|collect|redeem)\s+(?:your\s+)?(?:prize|reward|winnings|gift)",
    r"congratulations?\b",
    r"free\s+(?:gift|money|iphone|laptop|trip)",
]

IMPERSONATION_PATTERNS = [
    r"(?:from|sent\s+by)\s+(?:the\s+)?(?:security|support|admin|helpdesk|it)\s+team",
    r"(?:official|authorized)\s+(?:notice|notification|communication)",
    r"(?:dear|valued)\s+(?:customer|user|member|client)",
    r"(?:we\s+(?:have|are)\s+(?:noticed|detected)|this\s+is\s+to\s+(?:inform|notify))",
    r"(?:your\s+)?(?:account|service)\s+(?:with|at)\s+(?:us|our\s+(?:company|organization))",
]

# --- Database ---
DATABASE_PATH = "data/phishguard.db"

# --- ML Models ---
URL_MODEL_PATH = "backend/app/ml/models/url_model.joblib"
MESSAGE_MODEL_PATH = "backend/app/ml/models/message_model.joblib"
URL_SCALER_PATH = "backend/app/ml/models/url_scaler.joblib"
MESSAGE_VECTORIZER_PATH = "backend/app/ml/models/message_vectorizer.joblib"

# --- Application ---
APP_TITLE = "PhishGuard AI"
APP_VERSION = "1.0.0"
APP_DESCRIPTION = "AI-Based Multi-Layer Phishing Detection System"
CORS_ORIGINS = ["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173"]
CORS_ORIGIN_REGEX = r"https?://(localhost|127\.0\.0\.1):\d+"
