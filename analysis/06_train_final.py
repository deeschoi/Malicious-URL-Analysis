"""Train and persist the model the scanner serves.

One model is produced, over the 25 features still obtainable in 2026. It is
fitted on the grouped training partition and evaluated on the held-out grouped
partition, then refitted on the full dataset for serving. Both operating points
are chosen on the held-out partition so they are not tuned on data the served
model has memorised.

Features the live extractor cannot measure for a given URL are filled with the
extractor's documented fallback and flagged in the scan response, so a single
model degrades gracefully rather than needing a separate fallback estimator.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sklearn.base import clone

from phishing.config import ARTIFACTS_DIR, DEPLOYABLE_FEATURES, REPORTS_DIR, ensure_dirs
from phishing.data import grouped_split, load_xy
from phishing.evaluate import best_cost_threshold, metric_dict, threshold_report
from phishing.io import save_json
from phishing.models import build_models
from phishing.tuning import persist_model

MODEL_NAME = "XGBoost"

# Operating points the scanner exposes, as (false positive cost, false negative
# cost). "warn" weights both errors alike; "block" makes a false alarm ten times
# as expensive, because silently blocking a legitimate site is worse than
# showing a warning the user can dismiss.
OPERATING_POINTS = {"warn": (1.0, 1.0), "block": (10.0, 1.0)}


def main() -> None:
    ensure_dirs()
    X, y, groups = load_xy()
    X_tr, X_te, y_tr, y_te, _, _ = grouped_split(X, y, groups)

    features = list(DEPLOYABLE_FEATURES)
    print(f"=== Deployable model ({len(features)} features) ===")
    print(f"  {', '.join(features)}")

    template = build_models()[MODEL_NAME]
    evaluated = clone(template).fit(X_tr[features], y_tr)
    proba = evaluated.predict_proba(X_te[features])[:, 1]
    metrics = metric_dict(y_te, evaluated.predict(X_te[features]), proba)
    print(f"  held-out accuracy {metrics['accuracy']:.4f}  "
          f"auroc {metrics['auroc']:.4f}  brier {metrics['brier']:.4f}")

    thresholds = {}
    for name, (fp_cost, fn_cost) in OPERATING_POINTS.items():
        t, _ = best_cost_threshold(y_te, proba, fp_cost, fn_cost)
        report = threshold_report(y_te, proba, t)
        thresholds[name] = report
        print(f"  {name:5s} threshold {t:.3f} -> recall {report['recall']:.3f}, "
              f"false-positive rate {report['fpr']:.3f}")

    warn = thresholds["warn"]["threshold"]
    block = max(thresholds["block"]["threshold"], warn)

    # The scanner reports quality at the warn threshold, so store that view.
    served_metrics = dict(metrics)
    served_metrics["recall"] = thresholds["warn"]["recall"]
    served_metrics["fpr"] = thresholds["warn"]["fpr"]

    # Refit on everything for serving; the numbers above stay the honest estimate.
    served = clone(template).fit(X[features], y)
    path = persist_model(
        served,
        feature_names=features,
        threshold=warn,
        metrics=served_metrics,
        model_name=MODEL_NAME,
        notes="Grouped holdout evaluation; refitted on the full dataset for serving.",
        extra={"fpr_threshold": block, "operating_points": thresholds},
        path=ARTIFACTS_DIR / "model.joblib",
    )
    print(f"\n  saved to {path}")

    card = {
        "trained_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "dataset": "UCI Phishing Websites (Mohammad, Thabtah & McCluskey, 2012)",
        "n_rows": int(len(X)),
        "evaluation": "grouped holdout; no feature pattern shared between train and test",
        "n_train": int(len(X_tr)),
        "n_test": int(len(X_te)),
        "algorithm": "XGBoost (300 trees, depth 5, lr 0.08)",
        "features": features,
        "metrics": metrics,
        "thresholds": thresholds,
        "artifact": str(path),
    }
    save_json(card, REPORTS_DIR / "06_model_card.json")
    print(f"Model card written to {REPORTS_DIR / '06_model_card.json'}")


if __name__ == "__main__":
    main()
