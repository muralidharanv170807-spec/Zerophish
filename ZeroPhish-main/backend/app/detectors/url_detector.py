"""
PhishGuard AI — URL Detector
Extracts security features from URLs and produces structured indicators.
"""

import re
from ipaddress import ip_address
from urllib.parse import urlparse, parse_qs
from backend.app.config import (
    SUSPICIOUS_TLDS, SUSPICIOUS_KEYWORDS, URL_SHORTENERS, BRAND_DOMAINS
)

URL_PATTERN = re.compile(
    r"(?:https?://|www\.)[^\s<>{}|\\^`\[\]\"']+|"
    r"(?<![@\w])(?:(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|"
    r"(?:\d{1,3}\.){3}\d{1,3})(?::\d+)?"
    r"(?:[/?#][^\s<>{}|\\^`\[\]\"']*)?",
    re.IGNORECASE,
)


def extract_urls(text: str) -> list[str]:
    """Extract and normalize explicit links, bare domains, and IPv4 URLs."""
    urls = []
    for match in URL_PATTERN.findall(text):
        candidate = match.rstrip(".,;:!?)]}'\"")
        if not candidate:
            continue
        if not candidate.lower().startswith(("http://", "https://")):
            candidate = "http://" + candidate
        if candidate not in urls:
            urls.append(candidate)
    return urls


def extract_url_features(url: str) -> dict:
    """Extract numerical features from a URL for ML model input."""
    parsed = _safe_parse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    full = url.lower()

    features = {
        "url_length": len(url),
        "has_https": 1 if parsed.scheme == "https" else 0,
        "has_ip_address": 1 if _has_ip(hostname) else 0,
        "has_at_symbol": 1 if "@" in url else 0,
        "dot_count": full.count("."),
        "hyphen_count": full.count("-"),
        "subdomain_count": _count_subdomains(hostname),
        "path_length": len(path),
        "query_length": len(parsed.query or ""),
        "has_suspicious_tld": 1 if _has_suspicious_tld(hostname) else 0,
        "suspicious_keyword_count": _count_suspicious_keywords(full, hostname),
        "is_shortened": 1 if _is_shortened(hostname) else 0,
        "has_brand_impersonation": 1 if _has_brand_impersonation(hostname, full) else 0,
        "digit_count_in_domain": sum(c.isdigit() for c in hostname),
        "has_double_slash_redirect": 1 if "//" in path else 0,
        "special_char_count": sum(1 for c in full if c in "!#$%^&*()+={}[]|\\:\";<>?,"),
    }
    return features


def analyze_url(url: str) -> dict:
    """Analyze a URL and return structured security indicators."""
    parsed = _safe_parse(url)
    hostname = parsed.hostname or ""
    full = url.lower()
    indicators = []
    details = {}

    # 1. HTTP (not HTTPS)
    if parsed.scheme != "https":
        indicators.append("Non-secure HTTP connection")
        details["https"] = False
    else:
        details["https"] = True

    # 2. IP address in URL
    if _has_ip(hostname):
        indicators.append("IP address used instead of domain name")
        details["ip_address"] = True

    # 3. @ symbol
    if "@" in url:
        indicators.append("@ symbol in URL (possible redirect trick)")
        details["at_symbol"] = True

    # 4. Excessive length
    if len(url) > 75:
        indicators.append(f"Unusually long URL ({len(url)} characters)")
        details["long_url"] = True

    # 5. Suspicious TLD
    tld_match = _get_suspicious_tld(hostname)
    if tld_match:
        indicators.append(f"Suspicious top-level domain ({tld_match})")
        details["suspicious_tld"] = tld_match

    # 6. Suspicious keywords
    found_keywords = _find_suspicious_keywords(full, hostname)
    if found_keywords:
        indicators.append(f"Suspicious keywords in URL: {', '.join(found_keywords[:5])}")
        details["suspicious_keywords"] = found_keywords

    # 7. URL shortener
    if _is_shortened(hostname):
        indicators.append("URL shortening service detected")
        details["shortened"] = True

    # 8. Brand impersonation
    impersonated_brand = _detect_brand_impersonation(hostname, full)
    if impersonated_brand:
        indicators.append(f"Possible brand impersonation: {impersonated_brand}")
        details["brand_impersonation"] = impersonated_brand

    # 9. Excessive subdomains
    sub_count = _count_subdomains(hostname)
    if sub_count >= 3:
        indicators.append(f"Excessive subdomains ({sub_count} levels)")
        details["excessive_subdomains"] = sub_count

    # 10. Many hyphens in domain
    hyphen_count = hostname.count("-")
    if hyphen_count >= 3:
        indicators.append(f"Excessive hyphens in domain ({hyphen_count})")
        details["excessive_hyphens"] = hyphen_count

    # 11. Double slash redirect in path
    if "//" in (parsed.path or ""):
        indicators.append("Double-slash redirect pattern in path")
        details["double_slash"] = True

    # 12. Digits in domain
    digit_count = sum(c.isdigit() for c in hostname)
    if digit_count >= 4 and not _has_ip(hostname):
        indicators.append(f"High number of digits in domain ({digit_count})")
        details["digits_in_domain"] = digit_count

    # Compute indicator-based risk score (0-100)
    indicator_score = min(100, len(indicators) * 15)

    return {
        "indicators": indicators,
        "indicator_count": len(indicators),
        "indicator_score": indicator_score,
        "details": details,
        "features": extract_url_features(url),
    }


# --- Private helper functions ---

def _safe_parse(url: str):
    """Parse and validate a web URL, adding HTTP when no scheme is supplied."""
    value = url.strip()
    if not value or any(character.isspace() or ord(character) < 32 for character in value):
        raise ValueError("Enter a valid URL without whitespace.")
    scheme_match = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", value)
    if scheme_match and not value.lower().startswith(("http://", "https://")):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")
    if not scheme_match:
        value = "http://" + value

    try:
        parsed = urlparse(value)
        hostname = parsed.hostname
        parsed.port
    except ValueError as exc:
        raise ValueError("Enter a valid HTTP or HTTPS URL.") from exc

    if parsed.scheme.lower() not in {"http", "https"} or not hostname:
        raise ValueError("Enter a valid HTTP or HTTPS URL with a hostname.")
    return parsed


def _has_ip(hostname: str) -> bool:
    """Check whether the hostname is a valid IPv4 or IPv6 address."""
    try:
        ip_address(hostname)
    except ValueError:
        return False
    return True


def _count_subdomains(hostname: str) -> int:
    """Count subdomain levels."""
    parts = hostname.split(".")
    if len(parts) <= 2:
        return 0
    return len(parts) - 2


def _has_suspicious_tld(hostname: str) -> bool:
    return any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS)


def _get_suspicious_tld(hostname: str) -> str | None:
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            return tld
    return None


def _is_legit_brand_keyword(kw: str, hostname: str) -> bool:
    """Check if kw is a brand name belonging to its legitimate domain."""
    if kw in BRAND_DOMAINS and hostname:
        legit_domain = BRAND_DOMAINS[kw]
        if hostname == legit_domain or hostname.endswith("." + legit_domain):
            return True
    return False


def _count_suspicious_keywords(text: str, hostname: str = "") -> int:
    return sum(
        1 for kw in SUSPICIOUS_KEYWORDS
        if kw in text and not _is_legit_brand_keyword(kw, hostname)
    )


def _find_suspicious_keywords(text: str, hostname: str = "") -> list[str]:
    return [
        kw for kw in SUSPICIOUS_KEYWORDS
        if kw in text and not _is_legit_brand_keyword(kw, hostname)
    ]


def _is_shortened(hostname: str) -> bool:
    return any(
        hostname == shortener or hostname.endswith("." + shortener)
        for shortener in URL_SHORTENERS
    )


def _has_brand_impersonation(hostname: str, full_url: str) -> bool:
    return _detect_brand_impersonation(hostname, full_url) is not None


def _detect_brand_impersonation(hostname: str, full_url: str) -> str | None:
    """Detect if URL impersonates a known brand."""
    for brand, legit_domain in BRAND_DOMAINS.items():
        # Brand name appears in hostname but it's not the legitimate domain
        if brand in hostname and legit_domain not in hostname:
            return brand
        # Brand in subdomain with different base domain
        parts = hostname.split(".")
        if len(parts) >= 3:
            subdomain_part = ".".join(parts[:-2])
            if brand in subdomain_part and legit_domain not in hostname:
                return brand
    return None
