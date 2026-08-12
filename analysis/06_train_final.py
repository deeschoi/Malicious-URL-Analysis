"""Train and persist the models the scanner serves.

Two models are produced:

  primary  - the 8 features chosen by forward selection. Needs a URL parse, a TLS
             handshake, and one page fetch.
  fallback - URL string plus TLS certificate only, used when the page cannot be
             fetched at all.

Both are fitted on the grouped training partition, evaluated on the held-out
grouped test partition, then refitted on the full dataset for serving. Operating
thresholds are chosen on the held-out partition so they are not tuned on data the
final model has memorised.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import joblib
from sklearn.base import clone

from phishing.config import (
    FALLBACK_FEATURES,
    MODELS_DIR,
    PRIMARY_FEATURES,
    RESULTS_DIR,
    ensure_dirs,
)
from phishing.data import grouped_holdout, load_raw, split_xy
from phishing.evaluate import best_threshold, save_json, score_all, threshold_metrics
from phishing.models import build_models

# Operating points the scanner exposes. "warn" is tuned for balanced cost;
# "block" is tuned to make false alarms ten times as expensive as misses.
OPERATING_POINTS = {"warn": (1.0, 1.0), "block": (10.0, 1.0)}


def train_one(label: str, features: list[str], X, y, X_tr, X_te, y_tr, y_te) -> dict:
    print(f"\n=== {label} model ({len(features)} features) ===")
    print(f"  {', '.join(features)}")

    template = build_models()["XGBoost"]

    evaluated = clone(template).fit(X_tr[features], y_tr)
    proba = evaluated.predict_proba(X_te[features])[:, 1]
    metrics = score_all(y_te, evaluated.predict(X_te[features]), proba)
    print(f"  held-out accuracy {metrics['accuracy']:.4f}  "
          f"auroc {metrics['auroc']:.4f}  brier {metrics['brier']:.4f}")

    thresholds = {}
    for name, (fp_cost, fn_cost) in OPERATING_POINTS.items():
        t, _ = best_threshold(y_te, proba, fp_cost, fn_cost)
        m = threshold_metrics(y_te, proba, t)
        thresholds[name] = m
        print(f"  {name:5s} threshold {t:.3f} -> recall {m['recall']:.3f}, "
              f"false-positive rate {m['false_positive_rate']:.3f}")

    # Refit on everything for serving; the numbers above stay the honest estimate.
    served = clone(template).fit(X[features], y)
    joblib.dump(
        {"model": served, "features": features, "thresholds": thresholds,
         "metrics": metrics},
        MODELS_DIR / f"{label}.joblib",
    )
    print(f"  saved to {MODELS_DIR / f'{label}.joblib'}")

    return {"features": features, "metrics": metrics, "thresholds": thresholds}


def main() -> None:
    ensure_dirs()
    X, y = split_xy(load_raw())
    X_tr, X_te, y_tr, y_te, _ = grouped_holdout(X, y)

    card = {
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dataset": "UCI Phishing Websites (Mohammad, Thabtah & McCluskey, 2012)",
        "n_rows": int(len(X)),
        "evaluation": "grouped holdout; no feature pattern shared between train and test",
        "n_train": int(len(X_tr)),
        "n_test": int(len(X_te)),
        "algorithm": "XGBoost (400 trees, depth 6, lr 0.05)",
        "models": {},
    }

    card["models"]["primary"] = train_one(
        "primary", PRIMARY_FEATURES, X, y, X_tr, X_te, y_tr, y_te
    )
    card["models"]["fallback"] = train_one(
        "fallback", FALLBACK_FEATURES, X, y, X_tr, X_te, y_tr, y_te
    )

    save_json(card, RESULTS_DIR / "06_model_card.json")
    joblib.dump(card, MODELS_DIR / "model_card.joblib")
    print(f"\nModel card written to {RESULTS_DIR / '06_model_card.json'}")


if __name__ == "__main__":
    main()
