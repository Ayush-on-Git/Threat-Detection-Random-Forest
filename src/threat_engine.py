import re
import joblib
import pandas as pd
from urllib.parse import urlparse
from collections import Counter
import math

# ================================
# Load Model
# ================================

data = joblib.load("models/final_rf_model.pkl")
model = data["model"]
threshold = data["threshold"]

# ================================
# Trusted Domains (Demo Safe)
# ================================

TRUSTED_DOMAINS = [
    "google.com",
    "amazon.com",
    "microsoft.com",
    "apple.com",
    "github.com",
    "notion.com"
]

# ================================
# URL NORMALIZER
# ================================

def normalize_url(url):
    url = url.strip().lower()

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.hostname

    if domain:
        domain = domain.replace("www.", "")
    else:
        domain = ""

    return url, domain


# ================================
# FEATURE EXTRACTION
# ================================

def extract_features(domain):

    if not domain:
        return None

    features = {}

    length = len(domain)
    features["length"] = length
    features["dot_count"] = domain.count(".")
    features["hyphen_count"] = domain.count("-")

    features["digit_ratio"] = sum(c.isdigit() for c in domain) / length if length else 0

    prob = [v / length for v in Counter(domain).values()] if length else [0]
    features["entropy"] = -sum(p * math.log2(p) for p in prob if p > 0)

    suspicious_words = ["login", "secure", "verify", "account", "update", "bank"]
    features["suspicious_word"] = int(any(word in domain for word in suspicious_words))

    features["has_ip"] = int(bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", domain)))

    risky_tlds = ["xyz", "top", "club", "live", "online", "site", "info"]
    features["risky_tld"] = int(domain.split(".")[-1] in risky_tlds)

    popular_brands = ["paypal", "google", "amazon", "microsoft", "apple"]
    features["brand_in_domain"] = int(
        any(brand in domain and domain != brand + ".com" for brand in popular_brands)
    )

    features["subdomain_count"] = max(domain.count(".") - 1, 0)

    vowels = "aeiou"
    features["vowel_ratio"] = sum(c in vowels for c in domain) / length if length else 0

    return features


# ================================
# MAIN ANALYZER
# ================================

def analyze_url(url):

    full_url, domain = normalize_url(url)

    if not domain:
        return {
            "domain": "Invalid URL",
            "probability": 0,
            "prediction": 1,
            "threat_score": 100,
            "risk_level": "HIGH",
            "reasons": ["Invalid or malformed URL"]
        }

    # 🔥 DEMO SAFE RULE
    if domain in TRUSTED_DOMAINS:
        return {
            "domain": domain,
            "probability": 0.01,
            "prediction": 0,
            "threat_score": 5,
            "risk_level": "LOW",
            "reasons": ["Trusted legitimate domain"]
        }

    feat = extract_features(domain)
    df = pd.DataFrame([feat])

    prob = model.predict_proba(df)[0][1]
    prediction = int(prob >= threshold)

    # Base threat score from ML probability
    threat_score = int(prob * 100)
    reasons = []

    # ======================
    # ML + Feature Indicators
    # ======================

    if feat["risky_tld"]:
        threat_score += 8
        reasons.append("Risky top-level domain")

    if feat["suspicious_word"]:
        threat_score += 10
        reasons.append("Suspicious keyword detected")

    if feat["brand_in_domain"]:
        threat_score += 15
        reasons.append("Brand impersonation attempt")

    if feat["entropy"] > 3.5:
        threat_score += 8
        reasons.append("High entropy (random-looking domain)")

    if feat["digit_ratio"] > 0.3:
        threat_score += 8
        reasons.append("Excessive digits in domain")

    # ======================
    # ADVANCED URL HEURISTICS
    # ======================

    if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
        threat_score += 15
        reasons.append("IP-based URL detected")

    if "@" in full_url:
        threat_score += 20
        reasons.append("@ symbol obfuscation detected")

    if len(full_url) > 75:
        threat_score += 10
        reasons.append("Unusually long URL")

    if domain.count(".") > 3:
        threat_score += 8
        reasons.append("Multiple subdomains detected")

    if not full_url.startswith("https"):
        threat_score += 5
        reasons.append("Non-secure HTTP protocol")

    # ======================
    # Final Adjustments
    # ======================

    threat_score = min(threat_score, 100)

    if threat_score < 30:
        risk_level = "LOW"
    elif threat_score < 60:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"

    if not reasons:
        reasons.append("No major threat indicators detected")

    return {
        "domain": domain,
        "probability": round(prob, 4),
        "prediction": prediction,
        "threat_score": threat_score,
        "risk_level": risk_level,
        "reasons": reasons
    }