"""Assemble a 30-feature vector from a raw URL, with per-feature fallbacks."""

from __future__ import annotations

from typing import Literal

import pandas as pd

from phishing.config import (
    FEATURE_COLUMNS,
    TIER_A,
    TIER_B,
    TIER_C,
)
from phishing.features.content_features import extract_content_features, redirect_feature
from phishing.features.fetch import FetchResult, fetch_page
from phishing.features.infra_features import extract_infra_features, unavailable_features
from phishing.features.reachability import LiveProbe, assess_reachability
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
    timeout: int | None = None,
) -> tuple[pd.Series, list[FeatureWarning], LiveProbe]:
    """Extract features in CSV column order.

    ``tier='A'`` is offline URL parsing only. ``tier='B'`` adds a page fetch.
    ``tier='full'`` adds TLS/WHOIS/DNS. Features that cannot be computed are
    filled with 0 (suspicious / unknown) and a warning is recorded. This
    function never raises on extraction failure.

    The third return value is whether the host was actually observed. The
    model still scores placeholder features; callers must not treat that
    score as a live-site verdict when the probe is ``unreachable`` or
    ``fetch_failed``.
    """
    warnings: list[FeatureWarning] = []
    values: dict[str, int] = {c: 0 for c in FEATURE_COLUMNS}

    try:
        values.update(extract_url_features(url))
    except Exception as exc:  # noqa: BLE001
        values.update(_neutral_fill(TIER_A, f"URL parse failed: {exc}", warnings))

    probed = False
    page_fetched = False
    tls_inspected = False
    dns_ok: bool | None = None

    if tier in ("B", "full"):
        probed = True
        if fetch is not None:
            result = fetch
        elif timeout is not None:
            result = fetch_page(url, timeout=timeout)
        else:
            result = fetch_page(url)
        page_url = result.final_url or url
        if result.ok and result.soup is not None:
            page_fetched = True
            dns_ok = True
            try:
                values.update(extract_content_features(result, page_url))
            except Exception as exc:  # noqa: BLE001
                values.update(
                    _neutral_fill(TIER_B, f"content parse failed: {exc}", warnings)
                )
        else:
            if result.error_kind == "dns":
                dns_ok = False
            elif result.error_kind is not None:
                dns_ok = True
            values.update(
                _neutral_fill(
                    TIER_B,
                    f"page fetch failed: {result.error or 'no HTML'}",
                    warnings,
                )
            )
        values["Redirect"] = redirect_feature(result.n_redirects)

    if tier == "full":
        probed = True
        try:
            infra, infra_warnings, infra_dns_ok, tls_inspected = extract_infra_features(
                url
            )
            values.update(infra)
            warnings.extend(infra_warnings)
            if infra_dns_ok:
                dns_ok = True
            elif dns_ok is None:
                dns_ok = False
        except Exception as exc:  # noqa: BLE001
            values.update(_neutral_fill(TIER_C, f"infra lookup failed: {exc}", warnings))
            dead, dead_w = unavailable_features()
            values.update(dead)
            warnings.extend(dead_w)
            tls_inspected = False
            if dns_ok is None:
                dns_ok = False
    else:
        # Even in cheaper tiers, document that reputation features are unused.
        dead, dead_w = unavailable_features()
        values.update(dead)
        warnings.extend(dead_w)
        if tier == "A":
            values.update(_neutral_fill(TIER_B + TIER_C, "skipped (tier A)", warnings))
        elif tier == "B":
            values.update(_neutral_fill(TIER_C, "skipped (tier B)", warnings))

    probe = assess_reachability(
        probed=probed,
        dns_ok=dns_ok,
        page_fetched=page_fetched,
        tls_inspected=tls_inspected,
    )
    series = pd.Series({c: int(values[c]) for c in FEATURE_COLUMNS}, dtype="int64")
    return series, warnings, probe
