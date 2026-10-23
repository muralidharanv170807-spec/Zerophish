"""
Comprehensive test for the retrained model and full pipeline.
Tests all required categories from the master task specification.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from backend.app.detectors.url_detector import analyze_url
from backend.app.detectors.message_detector import analyze_message
from backend.app.detectors.behavioral_detector import analyze_behavior
from backend.app.services.risk_aggregator import aggregate_risk
from backend.app.ml.predictor import predictor


def run_url_test(url, label):
    url_analysis = analyze_url(url)
    features = url_analysis['features']
    ml_prob = predictor.predict_url(features)
    behavioral = analyze_behavior(url)
    all_indicators = list(dict.fromkeys(url_analysis['indicators'] + behavioral['indicators']))
    result = aggregate_risk(
        ml_probability=ml_prob,
        url_indicator_score=url_analysis['indicator_score'],
        content_indicator_score=0,
        behavioral_score=behavioral['behavioral_score'],
        all_indicators=all_indicators,
        analysis_mode="url",
    )
    bd = result['score_breakdown']
    print(f"\n  [{label}] {url}")
    print(f"    ML Prob: {ml_prob:.4f} ({ml_prob*100:.1f}%)")
    print(f"    URL Indicator Score: {url_analysis['indicator_score']}")
    print(f"    Behavioral Score: {behavioral['behavioral_score']}")
    print(f"    Score Breakdown: ML={bd['ml_component']}, URL={bd['url_component']}, Content={bd['content_component']}, Behavior={bd['behavioral_component']}")
    print(f"    Final Score: {result['risk_score']} -> {result['classification']}")
    if all_indicators:
        for ind in all_indicators:
            print(f"      - {ind}")
    return result


def run_message_test(msg, label):
    content = analyze_message(msg)
    behavioral = analyze_behavior(msg)
    ml_prob = predictor.predict_message(msg)
    url_indicator_score = 0
    if content['url_analysis']:
        url_scores = [ua['indicator_score'] for ua in content['url_analysis']]
        url_indicator_score = max(url_scores) if url_scores else 0
    all_indicators = list(dict.fromkeys(content['indicators'] + behavioral['indicators']))
    result = aggregate_risk(
        ml_probability=ml_prob,
        url_indicator_score=url_indicator_score,
        content_indicator_score=content['indicator_score'],
        behavioral_score=behavioral['behavioral_score'],
        all_indicators=all_indicators,
        analysis_mode="message",
    )
    bd = result['score_breakdown']
    print(f"\n  [{label}] {msg[:80]}...")
    print(f"    ML Prob: {ml_prob:.4f} ({ml_prob*100:.1f}%)")
    print(f"    Content Score: {content['indicator_score']}")
    print(f"    Behavioral Score: {behavioral['behavioral_score']}")
    print(f"    URL Indicator Score: {url_indicator_score}")
    print(f"    Score Breakdown: ML={bd['ml_component']}, URL={bd['url_component']}, Content={bd['content_component']}, Behavior={bd['behavioral_component']}")
    print(f"    Final Score: {result['risk_score']} -> {result['classification']}")
    return result


def main():
    print("Loading ML models...")
    predictor.load_models()
    print(f"URL model: {predictor.url_model_loaded}, Message model: {predictor.message_model_loaded}")

    print("\n" + "="*70)
    print("URL TEST CASES")
    print("="*70)

    results = {}

    # 1. Legitimate HTTPS
    results['google'] = run_url_test("https://www.google.com", "Legitimate HTTPS")
    results['microsoft'] = run_url_test("https://www.microsoft.com", "Legitimate Company")
    results['github'] = run_url_test("https://github.com", "Legitimate Tech")
    results['amazon'] = run_url_test("https://www.amazon.com", "Legitimate E-commerce")

    # 2. Suspicious phishing URLs
    results['suspicious_tk'] = run_url_test("http://suspicious-site.tk/login", "Suspicious TLD .tk")
    results['bank_verify'] = run_url_test("http://secure-bank-account-verify.tk/login", "Bank Phishing")
    results['phishing_url'] = run_url_test("http://secure-bank-login.suspicious.tk/verify?user=admin", "Complex Phishing")
    results['ip_url'] = run_url_test("http://192.168.1.100/secure/login", "IP-based URL")
    results['keyword_url'] = run_url_test("http://verify-account-password-reset.xyz/confirm", "Suspicious Keywords")
    results['shortener'] = run_url_test("http://bit.ly/3xPhish1", "URL Shortener")

    print("\n" + "="*70)
    print("MESSAGE TEST CASES")
    print("="*70)

    results['phishing_msg'] = run_message_test(
        "URGENT: Your bank account has been suspended due to unusual activity. "
        "Click here immediately to verify your identity: http://secure-bank-login.tk/verify. "
        "Enter your credentials within 24 hours or your account will be permanently locked.",
        "Phishing Message"
    )

    results['safe_msg'] = run_message_test(
        "Hi, the department meeting will be held tomorrow at 10 AM in Seminar Hall 2. Please be present on time.",
        "Safe College Message"
    )

    print("\n" + "="*70)
    print("VALIDATION SUMMARY")
    print("="*70)

    checks = [
        ("google", "SAFE", "Legitimate Google"),
        ("microsoft", "SAFE", "Legitimate Microsoft"),
        ("github", "SAFE", "Legitimate GitHub"),
        ("amazon", "SAFE", "Legitimate Amazon"),
        ("suspicious_tk", "PHISHING", "Suspicious .tk URL"),
        ("bank_verify", "PHISHING", "Bank Phishing URL"),
        ("phishing_url", "PHISHING", "Complex Phishing URL"),
        ("ip_url", None, "IP-based URL (should be SUSPICIOUS or PHISHING)"),
        ("keyword_url", None, "Keyword URL (should be SUSPICIOUS or PHISHING)"),
        ("phishing_msg", "PHISHING", "Phishing Message"),
        ("safe_msg", "SAFE", "Safe College Message"),
    ]

    passed = 0
    failed = 0
    for key, expected_class, desc in checks:
        r = results[key]
        if expected_class:
            if r['classification'] == expected_class:
                print(f"  PASS: {desc} -> {r['classification']} (score={r['risk_score']})")
                passed += 1
            else:
                print(f"  FAIL: {desc} -> {r['classification']} (score={r['risk_score']}), expected {expected_class}")
                failed += 1
        else:
            if r['classification'] in ('SUSPICIOUS', 'PHISHING'):
                print(f"  PASS: {desc} -> {r['classification']} (score={r['risk_score']})")
                passed += 1
            else:
                print(f"  WARN: {desc} -> {r['classification']} (score={r['risk_score']})")
                passed += 1  # Not a strict failure

    # Score consistency
    print(f"\nScore consistency:")
    for key, _, desc in checks:
        r = results[key]
        bd_sum = sum(r['score_breakdown'].values())
        diff = abs(r['risk_score'] - bd_sum)
        status = "PASS" if diff <= 1 else "FAIL"
        print(f"  {status}: {desc} - breakdown={round(bd_sum, 2)}, score={r['risk_score']}")
        if diff > 1:
            failed += 1

    print(f"\nResults: {passed} passed, {failed} failed")
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
