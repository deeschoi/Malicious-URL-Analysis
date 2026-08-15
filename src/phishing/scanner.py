"""Score a live URL and return the payload the web UI renders."""

from __future__ import annotations

import ipaddress
import math
import socket
from functools import lru_cache
from typing import Any
from urllib.parse import urlparse

import pandas as pd

from phishing.config import (
    ARTIFACTS_DIR,
    DEAD_FEATURE_REASON,
    FEATURE_COLUMNS,
    FEATURE_LABELS,
    GENERIC_VALUE,
    REPORTS_DIR,
    REVERSED_FEATURES,
    UNAVAILABLE_2026,
    VALUE_MEANING,
)
from phishing.features.extractor import url_to_features
from phishing.io import load_json
from phishing.schema import FeatureWarning, ModelArtifact
from phishing.tuning import load_model

BLOCKED_SCHEMES = {"file", "javascript", "data", "ftp", "mailto"}


class UnsafeTargetError(ValueError):
    """The URL points at a local or private address and will not be fetched."""


def _clean_json(value: Any) -> Any:
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        return None
    if isinstance(value, dict):
        return {k: _clean_json(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_clean_json(v) for v in value]
    return value


def _normalise_url(url: str) -> str:
    text = url.strip()
    if not text:
        raise ValueError("URL is empty.")
    lowered = text.lower()
    for scheme in BLOCKED_SCHEMES:
        if lowered.startswith(f"{scheme}:") or lowered.startswith(f"{scheme}://"):
            raise ValueError(f"Scheme {scheme!r} is not allowed.")
    if "://" not in text:
        text = "https://" + text
    parsed = urlparse(text)
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        raise ValueError("URL must use http or https.")
    if not parsed.hostname:
        raise ValueError("URL has no host.")
    return text


def _is_unsafe_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _assert_public_url(url: str) -> None:
    host = urlparse(url).hostname or ""
    lowered = host.lower().rstrip(".")
    if lowered in {"localhost", "localhost.localdomain"} or lowered.endswith(".localhost"):
        raise UnsafeTargetError("Refusing to scan a local address.")
    try:
        as_ip = ipaddress.ip_address(host)
    except ValueError:
        as_ip = None
    if as_ip is not None and _is_unsafe_ip(as_ip):
        raise UnsafeTargetError("Refusing to scan a private or local address.")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except (ValueError, IndexError):
            continue
        if _is_unsafe_ip(ip):
            raise UnsafeTargetError("Refusing to scan a private or local address.")


@lru_cache(maxsize=1)
def _loaded_model() -> tuple[Any, ModelArtifact]:
    path = ARTIFACTS_DIR / "model.joblib"
    if not path.exists():
        raise FileNotFoundError(
            f"No trained model at {path}. From the repo root run: python run.py train --tune"
        )
    return load_model(path)


def available_models() -> dict[str, dict[str, Any]]:
    try:
        _, artifact = _loaded_model()
    except FileNotFoundError:
        return {}
    metrics = artifact.metrics
    warn = float(artifact.threshold)
    block = float(artifact.extra.get("fpr_threshold", max(warn, 0.85)))
    return {
        artifact.model_name: {
            "features": list(artifact.feature_names),
            "metrics": metrics,
            "thresholds": {
                "warn": {
                    "threshold": warn,
                    "recall": float(metrics.get("recall", 0.0)),
                    "false_positive_rate": float(metrics.get("fpr", 0.0)),
                },
                "block": {
                    "threshold": block,
                    "recall": float(metrics.get("recall", 0.0)),
                    "false_positive_rate": float(metrics.get("fpr", 0.0)),
                },
            },
        }
    }


def _verdict(probability: float, warn: float, block: float) -> str:
    if probability >= block:
        return "phishing"
    if probability >= warn:
        return "suspicious"
    if probability >= 0.25:
        return "probably safe"
    return "legitimate"


def _value_meaning(feature: str, encoded: int) -> str:
    meanings = VALUE_MEANING.get(feature, GENERIC_VALUE)
    return meanings.get(encoded, GENERIC_VALUE.get(encoded, str(encoded)))


def _warning_by_feature(warnings: list[FeatureWarning]) -> dict[str, FeatureWarning]:
    return {w.feature: w for w in warnings}


def _measured(feature: str, warning_map: dict[str, FeatureWarning]) -> bool:
    if feature in UNAVAILABLE_2026:
        return False
    warning = warning_map.get(feature)
    if warning is None:
        return True
    message = warning.message.lower()
    return not any(token in message for token in ("skipped", "failed", "retired", "not queried"))


def _signals(
    feature_names: list[str],
    shap_row,
    feature_row: pd.Series,
    warning_map: dict[str, FeatureWarning],
    k: int = 12,
) -> list[dict[str, Any]]:
    import numpy as np

    order = np.argsort(-np.abs(shap_row))[:k]
    out = []
    for i in order:
        name = feature_names[i]
        contribution = float(shap_row[i])
        encoded = int(feature_row[name])
        warning = warning_map.get(name)
        measured = _measured(name, warning_map)
        toward = "phishing" if contribution >= 0 else "legitimate"
        out.append(
            {
                "feature": name,
                "label": FEATURE_LABELS.get(name, name),
                "contribution": contribution,
                "measured": measured,
                "value_meaning": _value_meaning(name, encoded),
                "encoding_unreliable": name in REVERSED_FEATURES,
                "evidence": (
                    warning.message
                    if warning and not measured
                    else _value_meaning(name, encoded)
                ),
                "direction": f"pushed toward {toward}",
            }
        )
    return out


def _rationale(verdict: str, signals: list[dict[str, Any]]) -> str:
    top = [s["label"] for s in signals[:2] if s.get("label")]
    joined = " and ".join(top) if top else "the extracted URL features"
    if verdict == "phishing":
        return f"This looks like phishing mainly because of {joined}."
    if verdict == "suspicious":
        return f"This is in the warning band; {joined} moved the score toward phishing."
    return f"This looks legitimate; {joined} pulled the score toward the safe side."


def _coverage(warning_map: dict[str, FeatureWarning], n_model_features: int) -> dict[str, Any]:
    page_fetched = _measured("URL_of_Anchor", warning_map) or _measured("Request_URL", warning_map)
    tls_checked = _measured("SSLfinal_State", warning_map)
    return {
        "page_fetched": page_fetched,
        "tls_checked": tls_checked,
        "features_used": n_model_features,
        "features_in_dataset": len(FEATURE_COLUMNS),
        "features_unavailable": len(UNAVAILABLE_2026),
    }


def _notes(warnings: list[FeatureWarning]) -> list[str]:
    notes = []
    seen = set()
    for warning in warnings:
        if warning.feature in UNAVAILABLE_2026:
            continue
        if "skipped" in warning.message.lower():
            continue
        key = warning.message
        if key in seen:
            continue
        seen.add(key)
        notes.append(f"{FEATURE_LABELS.get(warning.feature, warning.feature)}: {warning.message}")
    return notes[:8]


def scan(url: str, timeout: int = 8) -> dict[str, Any]:
    """Extract features, score with the deployable model, and explain the verdict."""
    normalised = _normalise_url(url)
    _assert_public_url(normalised)
    estimator, artifact = _loaded_model()
    features, warnings = url_to_features(normalised, tier="full", timeout=timeout)
    X = features[artifact.feature_names].to_frame().T
    probability = float(estimator.predict_proba(X)[:, 1][0])
    warn = float(artifact.threshold)
    block = float(artifact.extra.get("fpr_threshold", max(warn, 0.85)))
    verdict = _verdict(probability, warn, block)
    warning_map = _warning_by_feature(warnings)

    signals: list[dict[str, Any]] = []
    try:
        from phishing.explain import shap_values

        _, values = shap_values(estimator, X, background=X)
        signals = _signals(artifact.feature_names, values[0], features, warning_map)
    except Exception as exc:  # noqa: BLE001
        signals = []
        shap_error = f"SHAP unavailable: {exc}"
    else:
        shap_error = None

    metrics = artifact.metrics
    notes = _notes(warnings)
    if shap_error:
        notes.insert(0, shap_error)

    return {
        "url": normalised,
        "final_url": normalised,
        "verdict": verdict,
        "probability": probability,
        "rationale": _rationale(verdict, signals),
        "notes": notes,
        "error": None,
        "signals": signals,
        "coverage": _coverage(warning_map, len(artifact.feature_names)),
        "model": artifact.model_name,
        "model_quality": {
            "accuracy": float(metrics.get("accuracy", 0.0)),
            "auroc": float(metrics.get("auroc", 0.0)),
            "recall_at_warn": float(metrics.get("recall", 0.0)),
            "false_positive_rate_at_warn": float(metrics.get("fpr", 0.0)),
            "warn_threshold": warn,
            "block_threshold": block,
        },
        "prediction": "phishing" if probability >= warn else "legitimate",
        "threshold": warn,
        "warnings": [w.to_dict() for w in warnings],
        "features": features.to_dict(),
    }


def research_findings() -> dict[str, Any]:
    """Headline numbers for the Research findings tab."""

    leakage = load_json(REPORTS_DIR / "01_grouped_evaluation.json")
    shap_res = load_json(REPORTS_DIR / "03_shap.json")
    obsolescence = load_json(REPORTS_DIR / "04_obsolescence.json")
    minimal = load_json(REPORTS_DIR / "05_minimal_features.json")
    payload = {
        "leakage": leakage.get("leakage", {}),
        "models": leakage.get("results", []),
        "reversed_features": shap_res.get("reversed_features", []),
        "no_signal_features": shap_res.get("no_signal_features", []),
        "encoding_audit": shap_res.get("encoding_audit", []),
        "top_interactions": shap_res.get("interactions", [])[:6],
        "scenarios": obsolescence.get("scenarios", []),
        "minimal_feature_set": minimal.get("minimal_feature_set", []),
        "unavailable_features": [
            {"feature": f, "reason": DEAD_FEATURE_REASON[f]} for f in UNAVAILABLE_2026
        ],
    }
    return _clean_json(payload)
