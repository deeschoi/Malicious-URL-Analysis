"""Assemble a 30-feature vector from a raw URL, with per-feature fallbacks."""

from __future__ import annotations

from typing import Literal

import pandas as pd

from phishing.config import (
    FEATURE_COLUMNS,
    LEGITIMATE,
    TIER_A,
    TIER_B,
    TIER_C,
    UNAVAILABLE_2026,
)
from phishing.features.content_features import extract_content_features
from phishing.features.fetch import FetchResult, fetch_page
from phishing.features.infra_features import extract_infra_features, unavailable_features
from phishing.features.url_features import extract_url_features
from phishing.schema import FeatureWarning

Tier = Literal["A", "B", "full"]


def _neutral_fill(
    missing: list[str], reason: str, warnings: list[FeatureWarning]
) -> dict[str, int]:
    values = {}
    for name in missing:
        values[name] = 0
        warnings.append(FeatureWarning(name, reason, 0))
    return values


def url_to_features(
    url: str,
    tier: Tier = "full",
    fetch: FetchResult | None = None,
) -> tuple[pd.Series, list[FeatureWarning]]:
    """Extract features in CSV column order.

    ``tier='A'`` is offline URL parsing only. ``tier='B'`` adds a page fetch.
    ``tier='full'`` adds TLS/WHOIS/DNS. Features that cannot be computed are
    filled with 0 (suspicious / unknown) and a warning is recorded. This
    function never raises on extraction failure.
    """
    warnings: list[FeatureWarning] = []
    values: dict[str, int] = {c: 0 for c in FEATURE_COLUMNS}

    try:
        values.update(extract_url_features(url))
    except Exception as exc:  # noqa: BLE001
        values.update(_neutral_fill(TIER_A, f"URL parse failed: {exc}", warnings))

    if tier in ("B", "full"):
        result = fetch if fetch is not None else fetch_page(url)
        page_url = result.final_url or url
        if result.ok and result.soup is not None:
            try:
                values.update(extract_content_features(result, page_url))
            except Exception as exc:  # noqa: BLE001
                values.update(
                    _neutral_fill(TIER_B, f"content parse failed: {exc}", warnings)
                )
        else:
            values.update(
                _neutral_fill(
                    TIER_B,
                    f"page fetch failed: {result.error or 'no HTML'}",
                    warnings,
                )
            )
        if fetch is None:
            # Redirect is a content-tier feature but comes from the fetch itself.
            from phishing.features.content_features import redirect_feature

            values["Redirect"] = redirect_feature(result.n_redirects)

    if tier == "full":
        try:
            infra, infra_warnings = extract_infra_features(url)
            values.update(infra)
            warnings.extend(infra_warnings)
        except Exception as exc:  # noqa: BLE001
            values.update(_neutral_fill(TIER_C, f"infra lookup failed: {exc}", warnings))
            dead, dead_w = unavailable_features()
            values.update(dead)
            warnings.extend(dead_w)
    else:
        # Even in cheaper tiers, document that reputation features are unused.
        dead, dead_w = unavailable_features()
        values.update(dead)
        warnings.extend(dead_w)
        if tier == "A":
            values.update(_neutral_fill(TIER_B + TIER_C, "skipped (tier A)", warnings))
        elif tier == "B":
            values.update(_neutral_fill(TIER_C, "skipped (tier B)", warnings))

    series = pd.Series({c: int(values[c]) for c in FEATURE_COLUMNS}, dtype="int64")
    return series, warnings
