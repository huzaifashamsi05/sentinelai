"""
Shared pattern for every ML-backed module (Network IDS, Phishing, Malware):
load a joblib-pickled (model, feature_names, label_encoder, shap_explainer)
bundle, predict on new input, and return the top SHAP features as a
human-readable explanation. This is the one piece of logic that makes
every module "explainable" instead of a black box.
"""
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

from app.core.config import settings


_STANDARD_KEYS = {"model", "feature_names", "label_names", "explainer"}


@dataclass
class LoadedModel:
    model: Any
    feature_names: list[str]
    label_names: list[str]
    explainer: Any  # shap.TreeExplainer
    # Anything the joblib bundle carries beyond the 4 standard keys above
    # (e.g. network_ids' "categorical_encoders") — exposed here so callers
    # never need a second, separate joblib.load() of the same file just to
    # reach one extra field (see F-13: /predict used to reload the whole
    # 22 MB bundle from disk on every single request for exactly this reason).
    extra: dict = None  # type: ignore[assignment]


_cache: dict[str, LoadedModel] = {}


def load_bundle(module_key: str) -> LoadedModel | None:
    """module_key e.g. 'network_ids', 'phishing', 'malware'.
    Returns None if the model hasn't been trained/placed yet, so routers
    can return a clear 503 instead of crashing on import."""
    if module_key in _cache:
        return _cache[module_key]

    path = Path(settings.MODELS_DIR) / f"{module_key}.joblib"
    if not path.exists():
        return None

    bundle = joblib.load(path)
    loaded = LoadedModel(
        model=bundle["model"],
        feature_names=bundle["feature_names"],
        label_names=bundle["label_names"],
        explainer=bundle["explainer"],
        extra={k: v for k, v in bundle.items() if k not in _STANDARD_KEYS},
    )
    _cache[module_key] = loaded
    return loaded


def predict_with_explanation(loaded: LoadedModel, feature_row: dict, top_k: int = 5):
    """feature_row: dict of feature_name -> value (raw, already encoded to
    numeric — each module's router is responsible for feature engineering
    before calling this)."""
    X = pd.DataFrame([[feature_row.get(f, 0) for f in loaded.feature_names]], columns=loaded.feature_names)

    pred_idx = int(loaded.model.predict(X)[0])
    proba = loaded.model.predict_proba(X)[0]
    confidence = float(proba[pred_idx])
    label = loaded.label_names[pred_idx]

    shap_values = loaded.explainer.shap_values(X)
    # Multi-class TreeExplainer returns a list-per-class or a 3D array
    # depending on shap version; normalize to the predicted class's row.
    if isinstance(shap_values, list):
        row_shap = np.array(shap_values[pred_idx])[0]
    elif shap_values.ndim == 3:
        row_shap = shap_values[0, :, pred_idx]
    else:
        row_shap = shap_values[0]

    def to_native(v):
        """numpy scalars (int64/float32/bool_/...) aren't JSON-serializable —
        coerce to plain Python types before they reach FastAPI's encoder."""
        if isinstance(v, np.generic):
            return v.item()
        return v

    order = np.argsort(-np.abs(row_shap))[:top_k]
    explanation = [
        {
            "feature": loaded.feature_names[i],
            "value": to_native(X.iloc[0, i]),
            "impact": float(row_shap[i]),
        }
        for i in order
    ]

    return {
        "label": label,
        "confidence": confidence,
        "explanation": explanation,
        "pred_idx": pred_idx,
    }
