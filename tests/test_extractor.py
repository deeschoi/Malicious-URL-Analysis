"""Tier C helpers and extractor assembly. Network tests are opt-in."""

from __future__ import annotations

import pytest

from phishing.config import FEATURE_COLUMNS, UNAVAILABLE_2026
from phishing.features.content_features import redirect_feature
from phishing.features.extractor import url_to_features
from phishing.features.infra_features import port_feature, unavailable_features


def test_unavailable_features_are_neutral_with_warnings():
    values, warnings = unavailable_features()
    assert set(values) == set(UNAVAILABLE_2026)
    assert all(v == 0 for v in values.values())
    assert {w.feature for w in warnings} == set(UNAVAILABLE_2026)


def test_port_table():
    assert port_feature("https://example.com/") == 1
    assert port_feature("https://example.com:443/") == 1
    assert port_feature("http://example.com:80/") == 1
    assert port_feature("http://example.com:22/") == -1
    assert port_feature("http://example.com:3389/") == -1


def test_tier_a_extractor_offline_and_ordered():
    series, warnings = url_to_features("https://www.example.com/login", tier="A")
    assert list(series.index) == FEATURE_COLUMNS
    assert series.dtype == "int64"
    # Tier A should not need a network call; warnings cover skipped tiers.
    skipped = {w.feature for w in warnings}
    assert "SSLfinal_State" in skipped
    assert "URL_of_Anchor" in skipped


def test_redirect_csv_contract():
    assert redirect_feature(1) in (0, 1)
    assert redirect_feature(5) == 1


@pytest.mark.network
def test_full_extractor_example_com():
    series, warnings = url_to_features("https://example.com/", tier="full")
    assert list(series.index) == FEATURE_COLUMNS
    assert series["having_IP_Address"] == 1
    dead = [w for w in warnings if w.feature in UNAVAILABLE_2026]
    assert len(dead) == 5
