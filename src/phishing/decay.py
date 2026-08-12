"""Feature-set ablation, 2012-signal decay, and cheap-feature adversarial flips."""

from __future__ import annotations

from typing import Iterable

import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, clone

from phishing.config import (
    FEATURE_COLUMNS,
    LEGITIMATE,
    TIER_A,
    TIER_A_PLUS_B,
    TIER_A_PLUS_B_PLUS_C,
    UNAVAILABLE_2026,
)
from phishing.evaluate import metric_dict
from phishing.models import build_model

# How expensive it is for an attacker to flip a phishing indicator toward
# "looks legitimate". Units are arbitrary but ordered: 1 = free/trivial,
# 10 = requires money or waiting. Used only for ranking, not as a dollar cost.
ATTACKER_COST: dict[str, int] = {
    "having_At_Symbol": 1,
    "Prefix_Suffix": 1,
    "having_IP_Address": 1,
    "HTTPS_token": 1,
    "double_slash_redirecting": 1,
    "Shortining_Service": 2,
    "URL_Length": 2,
    "having_Sub_Domain": 2,
    "Iframe": 3,
    "popUpWidnow": 3,
    "RightClick": 3,
    "on_mouseover": 3,
    "Submitting_to_email": 3,
    "Favicon": 4,
    "Redirect": 4,
    "port": 4,
    "SFH": 5,
    "Request_URL": 6,
    "URL_of_Anchor": 6,
    "Links_in_tags": 6,
    "DNSRecord": 5,
    "Abnormal_URL": 5,
    "SSLfinal_State": 7,  # cheap in 2026 via Let's Encrypt; costly in 2012
    "Domain_registeration_length": 8,
    "age_of_domain": 9,
    "Google_Index": 8,
    "web_traffic": 10,
    "Page_Rank": 10,
    "Links_pointing_to_page": 9,
    "Statistical_report": 6,
}

TIER_SETS: dict[str, list[str]] = {
    "A_url_string": TIER_A,
    "A_plus_B_url_and_content": TIER_A_PLUS_B,
    "A_plus_B_plus_C_deployable": TIER_A_PLUS_B_PLUS_C,
    "all_30": FEATURE_COLUMNS,
}


def _fit_score(
    estimator: BaseEstimator,
    X_train: pd.DataFrame,
    y_train: pd.Series,
    X_test: pd.DataFrame,
    y_test: pd.Series,
    columns: list[str],
) -> dict[str, float]:
    model = clone(estimator)
    model.fit(X_train[columns], y_train)
    proba = model.predict_proba(X_test[columns])[:, 1]
    pred = (proba >= 0.5).astype(int)
    metrics = metric_dict(y_test, pred, proba)
    metrics["n_features"] = float(len(columns))
    return metrics


def tier_ablation(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    X_test: pd.DataFrame,
    y_test: pd.Series,
    model_name: str = "Random Forest",
    extra_sets: dict[str, list[str]] | None = None,
) -> pd.DataFrame:
    """Accuracy vs extraction cost: URL-only, +content, +infra, all 30."""
    estimator = build_model(model_name)
    sets = dict(TIER_SETS)
    if extra_sets:
        sets.update(extra_sets)
    rows = []
    for label, cols in sets.items():
        metrics = _fit_score(estimator, X_train, y_train, X_test, y_test, cols)
        metrics["feature_set"] = label
        rows.append(metrics)
    return pd.DataFrame(rows).set_index("feature_set")


def apply_decay(
    X: pd.DataFrame,
    ssl_to_legitimate: bool = True,
    neutralize_reputation: bool = True,
) -> pd.DataFrame:
    """Simulate 2026 conditions on a 2012 feature matrix.

    * Universal HTTPS: every row's ``SSLfinal_State`` is set to legitimate (1).
    * Retired reputation sources: ``web_traffic`` and ``Page_Rank`` are zeroed
      (the 'suspicious / unknown' code), matching 'source no longer exists'.
    """
    out = X.copy()
    if ssl_to_legitimate and "SSLfinal_State" in out.columns:
        out["SSLfinal_State"] = LEGITIMATE
    if neutralize_reputation:
        for col in ("web_traffic", "Page_Rank"):
            if col in out.columns:
                out[col] = 0
    return out


def decay_simulation(
    estimator: BaseEstimator,
    X_train: pd.DataFrame,
    y_train: pd.Series,
    X_test: pd.DataFrame,
    y_test: pd.Series,
    columns: list[str] | None = None,
) -> pd.DataFrame:
    """Score a fitted model on the original test set and on decayed copies."""
    columns = columns or list(X_train.columns)
    model = clone(estimator)
    model.fit(X_train[columns], y_train)

    scenarios = {
        "original_2012": X_test[columns],
        "universal_https": apply_decay(
            X_test[columns], ssl_to_legitimate=True, neutralize_reputation=False
        ),
        "dead_reputation": apply_decay(
            X_test[columns], ssl_to_legitimate=False, neutralize_reputation=True
        ),
        "https_and_dead_reputation": apply_decay(
            X_test[columns], ssl_to_legitimate=True, neutralize_reputation=True
        ),
        "drop_unavailable_2026": X_test[[c for c in columns if c not in UNAVAILABLE_2026]],
    }
    rows = []
    for name, Xt in scenarios.items():
        if name == "drop_unavailable_2026":
            cols = list(Xt.columns)
            m = clone(estimator)
            m.fit(X_train[cols], y_train)
            proba = m.predict_proba(Xt)[:, 1]
        else:
            proba = model.predict_proba(Xt)[:, 1]
        pred = (proba >= 0.5).astype(int)
        metrics = metric_dict(y_test, pred, proba)
        metrics["scenario"] = name
        rows.append(metrics)
    return pd.DataFrame(rows).set_index("scenario")


def cheapest_features(n: int | None = None) -> list[str]:
    ordered = sorted(ATTACKER_COST, key=ATTACKER_COST.get)
    return ordered if n is None else ordered[:n]


def flip_toward_legitimate(X: pd.DataFrame, columns: Iterable[str]) -> pd.DataFrame:
    """Set selected features to the legitimate encoding (1) on every row."""
    out = X.copy()
    for col in columns:
        if col in out.columns:
            out[col] = LEGITIMATE
    return out


def adversarial_curve(
    estimator: BaseEstimator,
    X_train: pd.DataFrame,
    y_train: pd.Series,
    X_test: pd.DataFrame,
    y_test: pd.Series,
    max_k: int = 12,
) -> pd.DataFrame:
    """Recall on phishing rows as an attacker flips the k cheapest features.

    Only phishing test rows are mutated; legitimate rows stay untouched so the
    curve isolates evasion, not a change in the negative class.
    """
    model = clone(estimator)
    model.fit(X_train, y_train)
    order = [c for c in cheapest_features() if c in X_test.columns]
    phish_mask = y_test.to_numpy() == 1
    rows = []
    for k in range(0, min(max_k, len(order)) + 1):
        Xt = X_test.copy()
        if k:
            Xt.loc[phish_mask, :] = flip_toward_legitimate(
                Xt.loc[phish_mask, :], order[:k]
            )
        proba = model.predict_proba(Xt)[:, 1]
        pred = (proba >= 0.5).astype(int)
        metrics = metric_dict(y_test, pred, proba)
        metrics["k"] = k
        metrics["flipped"] = ",".join(order[:k]) if k else ""
        rows.append(metrics)
    return pd.DataFrame(rows).set_index("k")
