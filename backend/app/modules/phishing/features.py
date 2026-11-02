"""
Lexical/structural feature engineering for the Phishing & Malicious URL
Detector. Every feature here is computed directly from the URL string —
no live network calls (DNS/WHOIS/domain-age lookups) — so the exact same
function is used both to build the training set and to score a URL
live in the API, with no train/serve skew.

IMPORTANT normalization note: the training dataset is overwhelmingly made
of bare "domain.com/path"-style entries with no "http(s)://" scheme and
almost no "www." prefix, in BOTH classes — a quirk of how it was
collected, not a property of phishing vs. legitimate URLs. Scoring a
real, fully-qualified URL a user actually pastes (e.g.
"https://www.github.com/...") against features trained on that
convention caused a systematic false positive: the model had learned
"has a scheme / has www" as a spurious signal. To avoid train/serve
distribution mismatch, we strip any "scheme://" and leading "www." before
computing structural features, so the model sees the same normalized
shape regardless of how the caller typed the URL. "uses_https_scheme" is
intentionally NOT a feature for this reason.

This is the single source of truth for phishing features: the training
script (ml/phishing/train.py) imports this same module.
"""
import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "bank", "confirm",
    "signin", "password", "webscr", "ebayisapi", "paypal", "billing",
    "suspend", "unlock", "wallet", "security",
]

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "cutt.ly", "rebrand.ly",
}

IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}")
SCHEME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")

FEATURE_NAMES = [
    "url_length", "hostname_length", "path_length",
    "num_dots", "num_hyphens", "num_underscores", "num_slashes",
    "num_digits", "num_special_chars", "num_subdomains",
    "has_ip_address", "has_at_symbol", "has_https_token_in_path",
    "has_suspicious_keyword", "is_url_shortener",
    "digit_ratio", "has_double_slash_redirect",
]


def _normalize(raw_url: str) -> str:
    """Strip scheme and a leading www. so features reflect the URL's
    actual shape, not how the caller happened to type the prefix."""
    url = raw_url.strip()
    url = SCHEME_PATTERN.sub("", url)
    if url.lower().startswith("www."):
        url = url[4:]
    return url


def extract_features(raw_url: str) -> dict:
    normalized = _normalize(raw_url)
    # urlparse needs *a* scheme to split host vs. path correctly.
    try:
        parsed = urlparse("http://" + normalized)
        hostname = parsed.netloc or ""
        path = parsed.path or ""
        query = parsed.query or ""
    except ValueError:
        # Malformed URL (e.g. stray brackets/invalid IPv6 literal) — still a
        # valid thing for a phishing detector to see, so fall back to
        # treating the whole string as an opaque path rather than crashing.
        hostname, path, query = "", normalized, ""

    full = normalized.lower()
    host_lower = hostname.lower()
    num_digits = sum(c.isdigit() for c in normalized)

    return {
        "url_length": len(normalized),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "num_dots": normalized.count("."),
        "num_hyphens": normalized.count("-"),
        "num_underscores": normalized.count("_"),
        "num_slashes": normalized.count("/"),
        "num_digits": num_digits,
        "num_special_chars": sum(normalized.count(c) for c in ["@", "%", "=", "&", "?", "~"]),
        "num_subdomains": max(host_lower.count(".") - 1, 0),
        "has_ip_address": int(bool(IP_PATTERN.match(host_lower))),
        "has_at_symbol": int("@" in normalized),
        "has_https_token_in_path": int("https" in (path.lower() + query.lower())),
        "has_suspicious_keyword": int(any(kw in full for kw in SUSPICIOUS_KEYWORDS)),
        "is_url_shortener": int(host_lower in SHORTENER_DOMAINS),
        "digit_ratio": round(num_digits / max(len(normalized), 1), 4),
        "has_double_slash_redirect": int(normalized.find("//") != -1),
    }
