"""
Trains the Network Intrusion Detection model on the NSL-KDD benchmark
dataset. Produces models/network_ids.joblib containing:
  { model, feature_names, label_names, explainer }
which backend/app/modules/network_ids/router.py loads at inference time.

Dataset: NSL-KDD (an improved, de-duplicated version of the classic
KDD Cup 1999 dataset), 41 traffic features + a label naming the specific
attack (or "normal"). We map the ~22 specific attack names down to 5
standard categories — normal / DoS / Probe / R2L / U2R — which is the
widely-used framing for this dataset and keeps classes learnable.

Run: python ml/network_ids/train.py
"""
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import shap
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, f1_score
from sklearn.preprocessing import LabelEncoder

ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = ROOT / "data" / "raw"
MODELS_DIR = ROOT / "models"
MODELS_DIR.mkdir(exist_ok=True)

COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label",
]

ATTACK_CATEGORY = {
    "normal": "normal",
    # DoS
    "back": "dos", "land": "dos", "neptune": "dos", "pod": "dos", "smurf": "dos",
    "teardrop": "dos", "apache2": "dos", "udpstorm": "dos", "processtable": "dos",
    "mailbomb": "dos", "worm": "dos",
    # Probe
    "satan": "probe", "ipsweep": "probe", "nmap": "probe", "portsweep": "probe",
    "mscan": "probe", "saint": "probe",
    # R2L (remote to local)
    "guess_passwd": "r2l", "ftp_write": "r2l", "imap": "r2l", "phf": "r2l",
    "multihop": "r2l", "warezmaster": "r2l", "warezclient": "r2l", "spy": "r2l",
    "xlock": "r2l", "xsnoop": "r2l", "snmpguess": "r2l", "snmpgetattack": "r2l",
    "httptunnel": "r2l", "sendmail": "r2l", "named": "r2l",
    # U2R (user to root)
    "buffer_overflow": "u2r", "loadmodule": "u2r", "perl": "u2r", "rootkit": "u2r",
    "ps": "u2r", "sqlattack": "u2r", "xterm": "u2r",
}


def load_split(filename: str) -> pd.DataFrame:
    df = pd.read_csv(DATA_DIR / filename, names=COLUMNS)
    df["label"] = df["label"].str.strip()
    df["category"] = df["label"].map(lambda x: ATTACK_CATEGORY.get(x, "other"))
    return df


def main():
    train_df = load_split("nsl_kdd_train.csv")
    test_df = load_split("nsl_kdd_test.csv")
    print(f"Train rows: {len(train_df)}, Test rows: {len(test_df)}")
    print("Category distribution (train):\n", train_df["category"].value_counts())

    categorical_cols = ["protocol_type", "service", "flag"]
    encoders = {c: LabelEncoder().fit(pd.concat([train_df[c], test_df[c]])) for c in categorical_cols}
    for c in categorical_cols:
        train_df[c] = encoders[c].transform(train_df[c])
        test_df[c] = encoders[c].transform(test_df[c])

    feature_cols = [c for c in COLUMNS if c != "label"]
    X_train, y_train_raw = train_df[feature_cols], train_df["category"]
    X_test, y_test_raw = test_df[feature_cols], test_df["category"]

    label_encoder = LabelEncoder().fit(pd.concat([y_train_raw, y_test_raw]))
    y_train = label_encoder.transform(y_train_raw)
    y_test = label_encoder.transform(y_test_raw)

    model = RandomForestClassifier(
        n_estimators=200, max_depth=20, min_samples_leaf=2,
        class_weight="balanced", n_jobs=-1, random_state=42,
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average="macro")
    print(f"\nTest accuracy: {acc:.4f}  |  Macro F1: {f1:.4f}\n")
    print(classification_report(y_test, y_pred, target_names=label_encoder.classes_, zero_division=0))

    print("Building SHAP TreeExplainer...")
    explainer = shap.TreeExplainer(model)

    bundle = {
        "model": model,
        "feature_names": feature_cols,
        "label_names": list(label_encoder.classes_),
        "explainer": explainer,
        "categorical_encoders": {c: list(encoders[c].classes_) for c in categorical_cols},
    }
    out_path = MODELS_DIR / "network_ids.joblib"
    joblib.dump(bundle, out_path)
    print(f"Saved model bundle -> {out_path}")

    metrics = {"accuracy": acc, "macro_f1": f1, "n_train": len(train_df), "n_test": len(test_df)}
    (MODELS_DIR / "network_ids_metrics.json").write_text(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
