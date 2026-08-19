"""Hyperparameter search under grouped cross-validation, plus model persistence."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import RandomizedSearchCV, StratifiedGroupKFold

from phishing.config import ARTIFACTS_DIR, N_SPLITS, RANDOM_STATE
from phishing.evaluate import best_f1_threshold, calibrate, metric_dict
from phishing.models import build_model
from phishing.schema import ModelArtifact

SEARCH_SPACES: dict[str, dict[str, list]] = {
    "Logistic Regression": {
        "C": [0.01, 0.1, 1.0, 10.0, 100.0, 1e10],
        "penalty": ["l2"],
        "solver": ["liblinear"],
    },
    "Random Forest": {
        "n_estimators": [200, 300, 500],
        "max_depth": [None, 12, 20],
        "min_samples_leaf": [1, 2, 4],
        "max_features": ["sqrt", 0.5],
    },
    "Gradient Boosting": {
        "n_estimators": [100, 150, 250],
        "learning_rate": [0.05, 0.1, 0.2],
        "max_depth": [2, 3, 4],
        "subsample": [0.8, 1.0],
    },
    "XGBoost": {
        "n_estimators": [200, 300, 500],
        "learning_rate": [0.03, 0.08, 0.15],
        "max_depth": [3, 5, 7],
        "subsample": [0.7, 0.9],
        "colsample_bytree": [0.7, 0.9],
        "min_child_weight": [1, 3],
    },
    "LightGBM": {
        "n_estimators": [200, 300, 500],
        "learning_rate": [0.03, 0.08, 0.15],
        "num_leaves": [15, 31, 63],
        "min_child_samples": [10, 20, 40],
        "subsample": [0.7, 0.9],
        "colsample_bytree": [0.7, 0.9],
    },
}


def grouped_random_search(
    name: str,
    X: pd.DataFrame,
    y: pd.Series,
    groups: np.ndarray,
    n_iter: int = 12,
    n_splits: int = N_SPLITS,
    scoring: str = "roc_auc",
    random_state: int = RANDOM_STATE,
) -> RandomizedSearchCV:
    """Tune ``name`` under StratifiedGroupKFold so search itself is leakage-free."""
    estimator = build_model(name)
    cv = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=random_state)
    search = RandomizedSearchCV(
        estimator,
        SEARCH_SPACES[name],
        n_iter=n_iter,
        scoring=scoring,
        cv=cv,
        random_state=random_state,
        n_jobs=-1,
        refit=True,
    )
    search.fit(X, y, groups=groups)
    return search


def tune_all(
    X: pd.DataFrame,
    y: pd.Series,
    groups: np.ndarray,
    names: list[str] | None = None,
    n_iter: int = 12,
) -> dict[str, RandomizedSearchCV]:
    names = names or list(SEARCH_SPACES)
    return {name: grouped_random_search(name, X, y, groups, n_iter=n_iter) for name in names}


def persist_model(
    estimator,
    feature_names: list[str],
    threshold: float,
    metrics: dict[str, float],
    model_name: str,
    notes: str = "",
    extra: dict[str, Any] | None = None,
    path: Path | None = None,
) -> Path:
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    path = path or (ARTIFACTS_DIR / "model.joblib")
    artifact = ModelArtifact(
        model_name=model_name,
        feature_names=list(feature_names),
        threshold=float(threshold),
        metrics={k: float(v) for k, v in metrics.items()},
        trained_at=datetime.now(UTC).isoformat(),
        notes=notes,
        extra=extra or {},
    )
    joblib.dump({"estimator": estimator, "artifact": artifact}, path)
    return path


def load_model(path: Path | None = None) -> tuple[Any, ModelArtifact]:
    path = path or (ARTIFACTS_DIR / "model.joblib")
    payload = joblib.load(path)
    return payload["estimator"], payload["artifact"]


def fit_deployable(
    name: str,
    X_train: pd.DataFrame,
    y_train: pd.Series,
    X_val: pd.DataFrame,
    y_val: pd.Series,
    groups_train: np.ndarray | None = None,
    tune: bool = True,
    calibrate_probs: bool = True,
) -> tuple[Any, float, dict[str, float]]:
    """Fit, optionally tune + calibrate, and pick a max-F1 threshold on ``X_val``."""
    if tune and groups_train is not None:
        search = grouped_random_search(name, X_train, y_train, groups_train)
        estimator = search.best_estimator_
        extra_note = f"best_params={search.best_params_}"
    else:
        estimator = build_model(name)
        estimator.fit(X_train, y_train)
        extra_note = "default hyperparameters"

    if calibrate_probs:
        estimator = calibrate(estimator, X_train, y_train, method="isotonic")

    proba = estimator.predict_proba(X_val)[:, 1]
    threshold, _ = best_f1_threshold(y_val, proba)
    pred = (proba >= threshold).astype(int)
    metrics = metric_dict(y_val, pred, proba)
    metrics["threshold"] = threshold
    metrics["note"] = extra_note  # type: ignore[assignment]
    return estimator, threshold, metrics
