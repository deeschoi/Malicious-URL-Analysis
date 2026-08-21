"""Score a live URL and return the payload the web UI renders."""

from __future__ import annotations

import ipaddress
import socket
from functools import lru_cache
from typing import Any
from urllib.parse import urlparse

import pandas as pd

from phishing.config import (
    ARTIFACTS_DIR,
    DEAD_FEATURE_REASON,
    FEATURE_LABELS,
    PHIUSIIL_MODEL_FEATURES,
    PHIUSIIL_URL_FEATURES,
    REPORTS_DIR,
    REVERSED_FEATURES,
    UNAVAILABLE_2026,
    VALUE_MEANING,
)
from phishing.features.extractor import url_to_phiusiil_features
from phishing.features.reachability import LiveProbe
from phishing.io import load_json, to_jsonable
from phishing.schema import FeatureWarning, ModelArtifact
from phishing.tuning import load_payload

BLOCKED_SCHEMES = {"file", "javascript", "data", "ftp", "mailto"}


class UnsafeTargetError(ValueError):
    """The URL points at a local or private address and will not be fetched."""


def _clean_json(value: Any) -> Any:
    return to_jsonable(value)


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
def _loaded_payload() -> dict[str, Any]:
    path = ARTIFACTS_DIR / "model.joblib"
    if not path.exists():
        raise FileNotFoundError(
            f"No trained model at {path}. From the repo root run: python run.py train --tune"
        )
    return load_payload(path)


def _loaded_model() -> tuple[Any, ModelArtifact]:
    payload = _loaded_payload()
    return payload["estimator"], payload["artifact"]


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


def _risk(probability: float, warn: float, block: float) -> str:
    if probability >= block:
        return "phishing"
    if probability >= warn:
        return "suspicious"
    if probability >= 0.25:
        return "probably safe"
    return "legitimate"


def _withhold_risk(probe: LiveProbe) -> bool:
    # DNS failure and offline scans are not live-site judgments. A fetch
    # timeout still has a fully measured URL string (scheme, host, path).
    return probe.status in {"unreachable", "not_probed"}


def _html_measured(probe: LiveProbe) -> bool:
    return bool(probe.page_fetched)


def _format_feature_value(feature: str, encoded: object) -> str:
    meanings = VALUE_MEANING.get(feature)
    try:
        as_int = int(encoded)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        as_int = None
    if (
        meanings is not None
        and as_int is not None
        and as_int in meanings
        and float(encoded) == as_int  # type: ignore[arg-type]
    ):
        return meanings[as_int]
    if isinstance(encoded, float) and not encoded.is_integer():
        return f"{encoded:.3f}"
    if isinstance(encoded, (int, float)):
        return str(int(encoded))
    return str(encoded)


def _warning_by_feature(warnings: list[FeatureWarning]) -> dict[str, FeatureWarning]:
    return {w.feature: w for w in warnings}


def _measured(feature: str, warning_map: dict[str, FeatureWarning]) -> bool:
    warning = warning_map.get(feature)
    if warning is None:
        return True
    message = warning.message.lower()
    return not any(
        token in message
        for token in ("skipped", "failed", "retired", "not queried", "unmeasured")
    )


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
        encoded = feature_row[name]
        warning = warning_map.get(name)
        measured = _measured(name, warning_map)
        toward = "phishing" if contribution >= 0 else "legitimate"
        meaning = _format_feature_value(name, encoded)
        out.append(
            {
                "feature": name,
                "label": FEATURE_LABELS.get(name, name),
                "contribution": contribution,
                "measured": measured,
                "value_meaning": meaning,
                "encoding_unreliable": name in REVERSED_FEATURES,
                "evidence": (
                    warning.message
                    if warning and not measured
                    else meaning
                ),
                "direction": f"pushed toward {toward}",
            }
        )
    return out


def _rationale(verdict: str, signals: list[dict[str, Any]], probe: LiveProbe) -> str:
    if probe.status == "unreachable":
        return (
            "The hostname does not resolve, so this is not a live-site judgment. "
            "DNS, TLS, and page fetch all failed; the score below is from the URL "
            "string and placeholders only."
        )
    if probe.status == "not_probed":
        return (
            "The page was not fetched. Risk is withheld; the score below is from "
            "the URL string only."
        )
    if verdict in {"phishing", "suspicious"}:
        top = [
            s["label"]
            for s in signals
            if s.get("label") and float(s.get("contribution", 0)) >= 0
        ][:2]
    else:
        top = [
            s["label"]
            for s in signals
            if s.get("label") and float(s.get("contribution", 0)) < 0
        ][:2]
    joined = " and ".join(top) if top else "the extracted URL features"
    if verdict == "phishing":
        text = f"This looks like phishing mainly because of {joined}."
    elif verdict == "suspicious":
        text = f"This is in the warning band; {joined} moved the score toward phishing."
    else:
        text = f"This looks legitimate; {joined} pulled the score toward the safe side."
    if probe.status == "fetch_failed":
        text += (
            " The page could not be fetched, so this is a URL-string score, not a "
            "live-page judgment."
        )
    return text


def _coverage(probe: LiveProbe, n_model_features: int) -> dict[str, Any]:
    return {
        "reachability": probe.status,
        "dns_ok": probe.dns_ok,
        "page_fetched": probe.page_fetched,
        "tls_checked": probe.tls_inspected,
        "features_used": n_model_features,
        "features_in_dataset": len(PHIUSIIL_MODEL_FEATURES),
        "features_unavailable": 0,
    }


_PLAIN_NOTES = (
    (
        "javascript shell",
        "This page is mostly JavaScript with almost no static links. Those "
        "missing links were not counted as a phishing signal.",
    ),
)


def _notes(warnings: list[FeatureWarning]) -> list[str]:
    notes = []
    seen = set()
    for warning in warnings:
        if warning.feature in UNAVAILABLE_2026:
            continue
        low = warning.message.lower()
        if "skipped" in low:
            continue
        if "page fetch failed" in low or "content parse failed" in low:
            continue
        # Minified HTML is the common case for 2026 sites; keep the fill, skip the note.
        if "minified html" in low:
            continue
        text = None
        for needle, plain in _PLAIN_NOTES:
            if needle in low:
                text = plain
                break
        if text is None:
            text = f"{FEATURE_LABELS.get(warning.feature, warning.feature)}: {warning.message}"
        if text in seen:
            continue
        seen.add(text)
        notes.append(text)
    return notes[:8]


def scan(
    url: str,
    timeout: int = 8,
    *,
    tier: str = "full",
    fetch=None,
) -> dict[str, Any]:
    """Extract features, score with the deployable model, and explain the verdict."""
    normalised = _normalise_url(url)
    _assert_public_url(normalised)
    payload = _loaded_payload()
    estimator, artifact = payload["estimator"], payload["artifact"]
    url_estimator = payload.get("url_estimator")
    tld_prob = artifact.extra.get("tld_legit_prob") or {}
    html_fill = artifact.extra.get("html_fill") or {}
    features, warnings, probe = url_to_phiusiil_features(
        normalised,
        tier=tier,  # type: ignore[arg-type]
        timeout=timeout,
        fetch=fetch,
        tld_prob=tld_prob,
        html_fill=html_fill,
    )
    withheld = _withhold_risk(probe)
    use_url_only = withheld or not _html_measured(probe)
    if use_url_only and url_estimator is not None:
        feature_names = list(artifact.extra.get("url_features") or PHIUSIIL_URL_FEATURES)
        scorer = url_estimator
        warn = float(artifact.extra.get("url_threshold", artifact.threshold))
        block = float(artifact.extra.get("url_fpr_threshold", max(warn, 0.85)))
        model_label = f"{artifact.model_name} (URL-only)"
        metrics = artifact.extra.get("url_metrics") or artifact.metrics
    else:
        feature_names = list(artifact.feature_names)
        scorer = estimator
        warn = float(artifact.threshold)
        block = float(artifact.extra.get("fpr_threshold", max(warn, 0.85)))
        model_label = artifact.model_name
        metrics = artifact.metrics

    X = features[feature_names].to_frame().T
    probability = float(scorer.predict_proba(X)[:, 1][0])
    risk = _risk(probability, warn, block)
    verdict = probe.status if withheld else risk
    warning_map = _warning_by_feature(warnings)

    signals: list[dict[str, Any]] = []
    try:
        from phishing.explain import shap_values

        _, values = shap_values(scorer, X, background=X)
        signals = _signals(feature_names, values[0], features, warning_map)
    except Exception as exc:  # noqa: BLE001
        signals = []
        shap_error = f"SHAP unavailable: {exc}"
    else:
        shap_error = None

    notes = _notes(warnings)
    if shap_error:
        notes.insert(0, shap_error)
    if use_url_only:
        if probe.status == "fetch_failed":
            fetch_note = (
                "The page could not be fetched. This score is from the URL string only."
            )
            if normalised.lower().startswith("http://"):
                fetch_note += (
                    " This dataset has no legitimate HTTP pages, so plain HTTP "
                    "scores as phishing."
                )
            notes.insert(0, fetch_note)
        else:
            notes.insert(
                0,
                "Page HTML was not measured; this probability comes from the URL-only model.",
            )

    payload_out = {
        "url": normalised,
        "final_url": normalised,
        "reachability": probe.to_dict(),
        "risk": None if withheld else risk,
        "verdict": verdict,
        "url_only": use_url_only,
        "probability": probability,
        "rationale": _rationale(verdict, signals, probe),
        "notes": notes,
        "error": None,
        "signals": signals,
        "coverage": _coverage(probe, len(feature_names)),
        "model": model_label,
        "model_quality": {
            "accuracy": float(metrics.get("accuracy", 0.0)),
            "auroc": float(metrics.get("auroc", 0.0)),
            "recall_at_warn": float(metrics.get("recall", 0.0)),
            "false_positive_rate_at_warn": float(metrics.get("fpr", 0.0)),
            "warn_threshold": warn,
            "block_threshold": block,
        },
        "prediction": (
            None if withheld else ("phishing" if probability >= warn else "legitimate")
        ),
        "threshold": warn,
        "warnings": [w.to_dict() for w in warnings],
        "features": features.to_dict(),
    }
    return _clean_json(payload_out)


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
