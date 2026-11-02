"""
Trains the Phishing/Malicious URL Detector.

Dataset: ~420k labeled URLs (good/bad) — a widely-used public malicious-URL
dataset. Features are purely lexical/structural (URL length, special
character counts, suspicious keywords, IP-address hosts, etc.) via
backend/app/modules/phishing/features.py, the SAME function used at
inference time — so there is no train/serve skew and no live network
calls (DNS/WHOIS) needed to score a URL.

Run: python ml/phishing/train.py
"""
import json
import re
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import shap
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, f1_score
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "backend"))
from app.modules.phishing.features import extract_features, FEATURE_NAMES  # noqa: E402

DATA_DIR = ROOT / "data" / "raw"
MODELS_DIR = ROOT / "models"
MODELS_DIR.mkdir(exist_ok=True)


def main():
    df = pd.read_csv(DATA_DIR / "malicious_urls_raw.csv", on_bad_lines="skip")
    df = df.dropna(subset=["url", "label"])
    print(f"Loaded {len(df)} URLs. Label distribution:\n{df['label'].value_counts()}")

    # Dataset is large (420k) and class-imbalanced (good >> bad); sample down
    # for a fast, still-plenty-large training set (keeps the demo snappy).
    bad = df[df["label"] == "bad"]
    good = df[df["label"] == "good"].sample(n=min(len(bad) * 3, len(df)), random_state=42)

    # --- Fix a real blind spot found during testing ---
    # EVERY "good" URL in this raw dataset has a path/resource after the
    # domain (it looks like it was collected from crawled content pages),
    # while ~3% of "bad" URLs are bare domains with nothing after them.
    # A tree model picks this up as "bare domain => malicious", which
    # misfires on exactly what a real user is most likely to paste: a
    # plain homepage URL like "https://www.google.com". We fix this by
    # teaching the model that a bare, reputable-looking domain is fine —
    # add every unique registrable domain already seen in the "good"
    # class back in as its own bare-domain example, plus a short list of
    # globally well-known domains.
    def registrable_domain(url: str) -> str:
        host = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", str(url)).split("/")[0]
        return host[4:] if host.lower().startswith("www.") else host

    bare_domains = good["url"].map(registrable_domain).dropna().unique()
    bare_domains = [d for d in bare_domains if "." in d][:40000]
    well_known = [
        "google.com", "youtube.com", "facebook.com", "wikipedia.org", "github.com",
        "microsoft.com", "apple.com", "amazon.com", "linkedin.com", "twitter.com",
        "instagram.com", "reddit.com", "netflix.com", "yahoo.com", "x.com",
        "whatsapp.com", "office.com", "zoom.us", "dropbox.com", "adobe.com",
    ]
    bare_df = pd.DataFrame({"url": list(set(bare_domains) | set(well_known)), "label": "good"})
    print(f"Augmenting with {len(bare_df)} bare-domain 'good' examples to fix the blind spot.")

    df = pd.concat([bad, good, bare_df]).sample(frac=1, random_state=42).reset_index(drop=True)
    print(f"Using balanced subset: {len(df)} rows ({len(bad)} bad / {len(good) + len(bare_df)} good)")

    print("Extracting lexical features from each URL...")
    feature_rows = [extract_features(u) for u in df["url"]]
    X = pd.DataFrame(feature_rows, columns=FEATURE_NAMES)
    y = (df["label"] == "bad").astype(int).values  # 1 = malicious/phishing, 0 = benign
    label_names = ["benign", "malicious"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    model = RandomForestClassifier(
        n_estimators=200, max_depth=18, min_samples_leaf=3,
        class_weight="balanced", n_jobs=-1, random_state=42,
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average="macro")
    print(f"\nTest accuracy: {acc:.4f}  |  Macro F1: {f1:.4f}\n")
    print(classification_report(y_test, y_pred, target_names=label_names, zero_division=0))

    print("Building SHAP TreeExplainer...")
    explainer = shap.TreeExplainer(model)

    bundle = {
        "model": model,
        "feature_names": FEATURE_NAMES,
        "label_names": label_names,
        "explainer": explainer,
    }
    out_path = MODELS_DIR / "phishing.joblib"
    joblib.dump(bundle, out_path)
    print(f"Saved model bundle -> {out_path}")

    metrics = {"accuracy": acc, "macro_f1": f1, "n_train": len(X_train), "n_test": len(X_test)}
    (MODELS_DIR / "phishing_metrics.json").write_text(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
