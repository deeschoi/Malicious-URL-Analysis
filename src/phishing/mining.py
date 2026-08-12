"""Association rules, k-modes phishing archetypes, and a depth-3 surrogate tree."""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.tree import DecisionTreeClassifier, export_text

from phishing.config import FEATURE_COLUMNS, RANDOM_STATE


def to_item_matrix(X: pd.DataFrame) -> pd.DataFrame:
    """One-hot each feature into items like ``SSLfinal_State=-1``."""
    frames = []
    for col in X.columns:
        dummies = pd.get_dummies(X[col], prefix=col, prefix_sep="=")
        frames.append(dummies)
    items = pd.concat(frames, axis=1)
    return items.astype(bool)


def mine_rules(
    X: pd.DataFrame,
    y: pd.Series,
    min_support: float = 0.08,
    min_confidence: float = 0.8,
    min_lift: float = 1.2,
    max_len: int = 3,
) -> pd.DataFrame:
    """FP-Growth rules whose consequent is the phishing class."""
    from mlxtend.frequent_patterns import association_rules, fpgrowth

    items = to_item_matrix(X)
    items["phishing=1"] = (y == 1).astype(bool)
    frequent = fpgrowth(items, min_support=min_support, use_colnames=True, max_len=max_len)
    if frequent.empty:
        return pd.DataFrame()
    rules = association_rules(frequent, metric="confidence", min_threshold=min_confidence)
    phishing_consequent = rules["consequents"].apply(lambda s: s == frozenset({"phishing=1"}))
    rules = rules[phishing_consequent].copy()
    rules = rules[rules["lift"] >= min_lift]
    rules["antecedents_str"] = rules["antecedents"].apply(
        lambda s: " AND ".join(sorted(s))
    )
    rules = rules.sort_values(["lift", "confidence", "support"], ascending=False)
    return rules[
        ["antecedents_str", "support", "confidence", "lift", "leverage", "conviction"]
    ].reset_index(drop=True)


def cluster_phishing(
    X: pd.DataFrame,
    y: pd.Series,
    n_clusters: int = 3,
    n_init: int = 5,
) -> tuple[np.ndarray, pd.DataFrame]:
    """k-modes clusters on the phishing subset. Returns labels aligned to X index."""
    from kmodes.kmodes import KModes

    phish = X.loc[y == 1]
    km = KModes(
        n_clusters=n_clusters,
        init="Huang",
        n_init=n_init,
        random_state=RANDOM_STATE,
        verbose=0,
    )
    labels = km.fit_predict(phish.to_numpy())
    aligned = pd.Series(-1, index=X.index, dtype=int)
    aligned.loc[phish.index] = labels
    centroids = pd.DataFrame(km.cluster_centroids_, columns=X.columns)
    sizes = pd.Series(labels).value_counts().sort_index()
    centroids.insert(0, "n_rows", sizes.values)
    return aligned.to_numpy(), centroids


def cluster_rule_crosstab(
    X: pd.DataFrame,
    cluster_labels: np.ndarray,
    rules: pd.DataFrame,
    top_n: int = 8,
) -> pd.DataFrame:
    """Share of each phishing cluster that matches the top association rules."""
    if rules.empty:
        return pd.DataFrame()
    phish_mask = cluster_labels >= 0
    rows = []
    for _, rule in rules.head(top_n).iterrows():
        items = [tok.strip() for tok in rule["antecedents_str"].split(" AND ")]
        match = pd.Series(True, index=X.index)
        for item in items:
            col, _, val = item.partition("=")
            match &= X[col] == int(val)
        for c in sorted(set(cluster_labels[phish_mask])):
            in_c = (cluster_labels == c) & phish_mask
            rows.append(
                {
                    "rule": rule["antecedents_str"],
                    "cluster": int(c),
                    "match_rate": float(match[in_c].mean()) if in_c.any() else 0.0,
                    "n_cluster": int(in_c.sum()),
                }
            )
    return pd.DataFrame(rows)


def surrogate_tree(
    X: pd.DataFrame,
    y_hat: np.ndarray,
    max_depth: int = 3,
    feature_names: list[str] | None = None,
) -> tuple[DecisionTreeClassifier, str]:
    """Shallow tree fitted on a black-box model's predictions, not the labels."""
    tree = DecisionTreeClassifier(max_depth=max_depth, random_state=RANDOM_STATE)
    tree.fit(X, y_hat)
    names = feature_names or list(X.columns)
    text = export_text(tree, feature_names=list(names), decimals=0)
    return tree, text
