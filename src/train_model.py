import pandas as pd
import numpy as np
import joblib
import re
import math
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    precision_score,
    recall_score
)
from sklearn.calibration import CalibratedClassifierCV


# =====================================
# Feature Engineering
# =====================================

def domain_entropy(domain):
    prob = [float(domain.count(c)) / len(domain) for c in dict.fromkeys(list(domain))]
    return -sum([p * math.log2(p) for p in prob])

def extract_features(domain):
    domain = domain.lower()
    features = {}

    features["length"] = len(domain)
    features["dot_count"] = domain.count(".")
    features["hyphen_count"] = domain.count("-")
    features["digit_ratio"] = sum(c.isdigit() for c in domain) / len(domain)
    features["entropy"] = domain_entropy(domain)

    suspicious_words = ["login", "secure", "verify", "account", "update", "bank"]
    features["suspicious_word"] = int(any(word in domain for word in suspicious_words))

    features["has_ip"] = int(bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", domain)))

    risky_tlds = ["xyz", "top", "club", "live", "online", "site", "info"]
    features["risky_tld"] = int(domain.split(".")[-1] in risky_tlds)

    popular_brands = ["paypal", "google", "amazon", "microsoft", "apple"]
    features["brand_in_domain"] = int(
        any(brand in domain and not domain.startswith(brand + ".") for brand in popular_brands)
    )

    features["subdomain_count"] = max(domain.count(".") - 1, 0)

    vowels = "aeiou"
    features["vowel_ratio"] = sum(c in vowels for c in domain) / len(domain)

    return features


# =====================================
# Load Dataset
# =====================================

df = pd.read_csv("data/final_balanced_dataset.csv")

X = pd.DataFrame([extract_features(d) for d in df["domain"]])
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    stratify=y,
    random_state=42
)


# =====================================
# Grid Search
# =====================================

param_grid = {
    "n_estimators": [400, 600, 800],
    "max_depth": [12, 16, None],
    "min_samples_split": [2, 4, 6],
    "min_samples_leaf": [1, 2, 3],
    "max_features": ["sqrt", "log2"]
}

base_model = RandomForestClassifier(
    class_weight="balanced",
    n_jobs=-1,
    random_state=42
)

grid_search = GridSearchCV(
    estimator=base_model,
    param_grid=param_grid,
    cv=3,
    scoring="roc_auc",
    verbose=2,
    n_jobs=-1
)

print("\nRunning GridSearch...")
grid_search.fit(X_train, y_train)

print("\nBest Parameters Found:")
print(grid_search.best_params_)

rf_model = grid_search.best_estimator_


# =====================================
# Probability Calibration (FIXED)
# =====================================

print("\nApplying Probability Calibration...")

calibrated_model = CalibratedClassifierCV(
    estimator=rf_model,   # 🔥 FIXED HERE
    method="sigmoid",
    cv=3
)

calibrated_model.fit(X_train, y_train)
model = calibrated_model


# =====================================
# Evaluation
# =====================================

y_prob = model.predict_proba(X_test)[:, 1]

print("\nROC-AUC Score:", roc_auc_score(y_test, y_prob))

print("\n--- Threshold Analysis ---")

best_threshold = 0.3  # phishing me recall important hota hai

for t in np.arange(0.25, 0.56, 0.05):
    y_pred = (y_prob >= t).astype(int)
    print(
        f"Threshold {t:.2f} -> "
        f"Precision: {precision_score(y_test, y_pred):.3f}, "
        f"Recall: {recall_score(y_test, y_pred):.3f}"
    )

print(f"\nSelected Threshold: {best_threshold}")

y_pred_final = (y_prob >= best_threshold).astype(int)

print("\nClassification Report:")
print(classification_report(y_test, y_pred_final))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred_final))


# =====================================
# Feature Importance
# =====================================

importance_df = pd.DataFrame({
    "feature": X.columns,
    "importance": rf_model.feature_importances_
}).sort_values(by="importance", ascending=False)

print("\nFeature Importance:")
print(importance_df)

plt.figure()
plt.bar(importance_df["feature"], importance_df["importance"])
plt.xticks(rotation=45)
plt.title("Feature Importance")
plt.tight_layout()
plt.close()


# =====================================
# Save Model
# =====================================

joblib.dump({
    "model": model,
    "feature_columns": X.columns.tolist(),
    "threshold": best_threshold
}, "models/final_rf_model.pkl")

print("\nModel saved successfully.")


# =====================================
# Manual Testing
# =====================================

print("\n--- Manual Domain Testing ---")

test_domains = [
    "google.com",
    "amazon.com",
    "microsoft.com",
    "paypal-secure-login.com",
    "free-bitcoin-now.xyz",
    "secure-update-account.xyz",
    "apple-support-login.live",
    "ghkdfkjh.biz",
    "login-bank-update.com"
]

for d in test_domains:
    feat = pd.DataFrame([extract_features(d)])
    prob = model.predict_proba(feat)[0][1]
    prediction = int(prob >= best_threshold)
    print(f"{d} -> Malicious Probability: {prob:.4f} | Prediction: {prediction}")