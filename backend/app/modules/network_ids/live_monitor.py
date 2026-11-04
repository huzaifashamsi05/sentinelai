"""
Turns logged HTTP requests (app/core/request_monitor.py) into NSL-KDD-style
connection feature rows and classifies them with the exact same trained
model used by this page's manual "Classify Traffic" form
(app/modules/ml_common.py + models/network_ids.joblib) — this is a second
front door onto the same classifier, not a separate detector.

Honest mapping, field by field — what's real and what's approximated:

- protocol_type is always "tcp": every request here travels over a TCP
  connection, so this is simply true, not a guess.
- service is always "http": this backend only ever serves HTTP, so again
  this is the real value.
- flag (the original dataset's raw TCP connection-state flag) is
  approximated from the HTTP status code, because the ASGI layer never
  exposes raw TCP flags to application code: 2xx/3xx -> "SF" (normal,
  established), 4xx -> "REJ" (rejected), 5xx -> "RSTO" (reset on error).
- count / srv_count and every *_rate derived from them reuse NSL-KDD's
  OWN definition verbatim: a rolling count over the last 2 seconds of
  REAL logged requests from the same client (count) or to the same path
  (srv_count), with error/same-service rates computed over that same
  real window. Nothing synthetic — just real events, really counted.
- dst_host_* features reuse NSL-KDD's other definition verbatim: computed
  over the last 100 REAL logged requests to this destination host. There
  is only one destination host in this deployment (this backend), so
  that window is simply the last 100 rows of the real log.
- num_failed_logins / logged_in use the only honest HTTP-layer signal
  available: recent 401s on the login endpoint, and whether this request
  itself carried an Authorization header.
- Every field with no honest HTTP-layer equivalent (root_shell,
  num_compromised, su_attempted, is_host_login, ...) is left at 0 rather
  than guessed — exactly like the manual form on this same page, which
  also defaults them to 0.

See the page's "What 'live' means here" panel for the plain-English
version of this — this module is the implementation, that panel is the
disclosure.
"""
from __future__ import annotations

from pathlib import Path

import joblib

from app.core.config import settings
from app.modules.ml_common import load_bundle, predict_with_explanation

MODULE_KEY = "network_ids"
_LOGIN_PATH_HINT = "/auth/login"
_TIME_WINDOW_SECONDS = 2.0   # NSL-KDD's own window for count/srv_count
_HOST_WINDOW_SIZE = 100      # NSL-KDD's own window for dst_host_*

_encoder_cache: dict[str, dict] = {}


def _get_encoders() -> dict:
    """Cached separately from ml_common's LoadedModel (which doesn't carry
    the raw categorical encoders) so a feed of N entries doesn't re-read
    the joblib file off disk N times per poll."""
    if MODULE_KEY not in _encoder_cache:
        raw_bundle = joblib.load(Path(settings.MODELS_DIR) / f"{MODULE_KEY}.joblib")
        _encoder_cache[MODULE_KEY] = raw_bundle["categorical_encoders"]
    return _encoder_cache[MODULE_KEY]


def _flag_for_status(status_code: int) -> str:
    if status_code <= 0:
        return "S0"
    if 200 <= status_code < 400:
        return "SF"
    if 400 <= status_code < 500:
        return "REJ"
    return "RSTO"


def _rate(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def compute_feature_row(entry, all_entries: list) -> dict:
    """all_entries must be oldest-first (request_monitor.all_entries()'s
    own ordering) and must include `entry` itself."""
    up_to_now = [e for e in all_entries if e.id <= entry.id]

    time_window = [e for e in up_to_now if entry.ts - e.ts <= _TIME_WINDOW_SECONDS]
    same_host = [e for e in time_window if e.client_ip == entry.client_ip]
    same_srv = [e for e in same_host if e.path == entry.path]

    count = len(same_host)
    srv_count = len(same_srv)
    serror = sum(1 for e in same_host if e.status_code >= 500)
    rerror = sum(1 for e in same_host if 400 <= e.status_code < 500)

    host_window = up_to_now[-_HOST_WINDOW_SIZE:]
    dst_host_count = len(host_window)
    dst_host_srv = [e for e in host_window if e.path == entry.path]
    dst_host_srv_count = len(dst_host_srv)
    dst_host_serror = sum(1 for e in host_window if e.status_code >= 500)
    dst_host_rerror = sum(1 for e in host_window if 400 <= e.status_code < 500)

    recent_login_fails = sum(
        1 for e in time_window if _LOGIN_PATH_HINT in e.path and e.status_code == 401
    )

    return {
        "duration": round(entry.duration_ms / 1000, 4),
        "protocol_type": "tcp",
        "service": "http",
        "flag": _flag_for_status(entry.status_code),
        "src_bytes": entry.req_bytes,
        "dst_bytes": entry.resp_bytes,
        "land": 0, "wrong_fragment": 0, "urgent": 0, "hot": 0,
        "num_failed_logins": recent_login_fails,
        "logged_in": 1 if entry.authenticated else 0,
        "num_compromised": 0, "root_shell": 0, "su_attempted": 0, "num_root": 0,
        "num_file_creations": 0, "num_shells": 0, "num_access_files": 0,
        "num_outbound_cmds": 0, "is_host_login": 0, "is_guest_login": 0,
        "count": count, "srv_count": srv_count,
        "serror_rate": _rate(serror, count), "srv_serror_rate": _rate(serror, srv_count),
        "rerror_rate": _rate(rerror, count), "srv_rerror_rate": _rate(rerror, srv_count),
        "same_srv_rate": _rate(srv_count, count), "diff_srv_rate": _rate(count - srv_count, count),
        "srv_diff_host_rate": 0.0,
        "dst_host_count": dst_host_count, "dst_host_srv_count": dst_host_srv_count,
        "dst_host_same_srv_rate": _rate(dst_host_srv_count, dst_host_count),
        "dst_host_diff_srv_rate": _rate(dst_host_count - dst_host_srv_count, dst_host_count),
        "dst_host_same_src_port_rate": 0.0, "dst_host_srv_diff_host_rate": 0.0,
        "dst_host_serror_rate": _rate(dst_host_serror, dst_host_count),
        "dst_host_srv_serror_rate": _rate(dst_host_serror, dst_host_srv_count),
        "dst_host_rerror_rate": _rate(dst_host_rerror, dst_host_count),
        "dst_host_srv_rerror_rate": _rate(dst_host_rerror, dst_host_srv_count),
    }


def classify_entry(entry, all_entries: list) -> dict | None:
    """Returns None only if the model bundle isn't loaded (mirrors the
    manual /predict endpoint's own 503 condition) — callers should treat
    that the same way the manual form's page already does."""
    bundle = load_bundle(MODULE_KEY)
    if bundle is None:
        return None

    feature_row = compute_feature_row(entry, all_entries)
    encoders = _get_encoders()

    def encode(field: str, value: str) -> int:
        classes = encoders[field]
        return classes.index(value) if value in classes else 0

    encoded_row = dict(feature_row)
    encoded_row["protocol_type"] = encode("protocol_type", feature_row["protocol_type"])
    encoded_row["service"] = encode("service", feature_row["service"])
    encoded_row["flag"] = encode("flag", feature_row["flag"])

    result = predict_with_explanation(bundle, encoded_row, top_k=4)
    return {
        "label": result["label"],
        "confidence": result["confidence"],
        "explanation": result["explanation"],
        "feature_row": feature_row,  # pre-encoding, human-readable — shown in the UI for transparency
    }
