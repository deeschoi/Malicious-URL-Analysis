"""Smoke tests for evaluation helpers, decay, and mining."""

from __future__ import annotations

import numpy as np

from phishing.config import LEGITIMATE
from phishing.data import load_xy
from phishing.decay import apply_decay, cheapest_features, flip_toward_legitimate
from phishing.evaluate import best_f1_threshold, fpr_target_threshold
from phishing.mining import surrogate_tree, to_item_matrix
from phishing.models import build_model


def test_build_all_models():
    for name in ("Logistic Regression", "Random Forest", "Gradient Boosting"):
        est = build_model(name)
        est.fit([[0, 1], [1, 0], [0, 0], [1, 1]], [0, 1, 0, 1])
        proba = est.predict_proba([[0, 1]])
        assert proba.shape == (1, 2)


def test_thresholds_on_separable_scores():
    y = np.array([0, 0, 0, 1, 1, 1])
    p = np.array([0.1, 0.2, 0.3, 0.7, 0.8, 0.9])
    t, f1 = best_f1_threshold(y, p)
    assert 0.3 < t <= 0.7
    assert f1 == 1.0
    t_fpr, fpr = fpr_target_threshold(y, p, max_fpr=0.01)
    assert fpr <= 0.01 + 1e-9


def test_apply_decay_sets_ssl_and_reputation():
    X, y, _ = load_xy()
    sample = X.head(20).copy()
    decayed = apply_decay(sample)
    assert (decayed["SSLfinal_State"] == LEGITIMATE).all()
    assert (decayed["web_traffic"] == 0).all()
    assert (decayed["Page_Rank"] == 0).all()
    assert (sample["having_IP_Address"] == decayed["having_IP_Address"]).all()


def test_adversary_flips_cheapest_first():
    order = cheapest_features(3)
    assert order[0] in {"having_At_Symbol", "Prefix_Suffix", "having_IP_Address", "HTTPS_token"}
    X, _, _ = load_xy()
    flipped = flip_toward_legitimate(X.head(5), order)
    for col in order:
        assert (flipped[col] == LEGITIMATE).all()


def test_item_matrix_and_surrogate():
    X, y, _ = load_xy()
    items = to_item_matrix(X.head(50))
    assert items.shape[0] == 50
    assert items.dtypes.eq(bool).all()
    tree, text = surrogate_tree(X.head(200), y.head(200).to_numpy(), max_depth=3)
    assert "SSLfinal_State" in text or "URL_of_Anchor" in text
    assert tree.get_depth() <= 3
