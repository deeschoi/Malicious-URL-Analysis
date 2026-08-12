"""CLI: train, evaluate, and scan a live URL.

Usage (from the repo root)::

    PYTHONPATH=src python -m phishing.cli evaluate
    PYTHONPATH=src python -m phishing.cli train
    PYTHONPATH=src python -m phishing.cli scan https://example.com
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

from phishing.config import (
    ARTIFACTS_DIR,
    DEPLOYABLE_FEATURES,
    FEATURE_COLUMNS,
    FIGURES_DIR,
    REPORTS_DIR,
    RISK_BANDS,
)
from phishing.data import grouped_split, load_xy
from phishing.decay import adversarial_curve, decay_simulation, tier_ablation
from phishing.evaluate import (
    best_f1_threshold,
    fpr_target_threshold,
    leakage_delta_table,
    metric_dict,
    threshold_report,
)
from phishing.models import ALL_MODELS, NOTEBOOK_MODELS, build_model
from phishing.tuning import persist_model


def _ensure_dirs() -> None:
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)


def _risk_band(probability: float) -> str:
    for lo, hi, name in RISK_BANDS:
        if lo <= probability < hi:
            return name
    return "critical"


def cmd_evaluate(args: argparse.Namespace) -> int:
    _ensure_dirs()
    X, y, groups = load_xy()
    names = NOTEBOOK_MODELS if args.quick else ALL_MODELS
    print(f"Computing leakage-delta table for: {', '.join(names)}")
    table = leakage_delta_table(X, y, groups, model_names=names)
    out = REPORTS_DIR / "leakage_delta.csv"
    table.to_csv(out)
    print(table.round(4).to_string())
    print(f"\nWrote {out}")
    return 0


def cmd_train(args: argparse.Namespace) -> int:
    """Train the 25-feature deployable model and persist it."""
    _ensure_dirs()
    X, y, groups = load_xy()
    X = X[DEPLOYABLE_FEATURES]
    X_tr, X_te, y_tr, y_te, g_tr, g_te = grouped_split(X, y, groups)

    candidates = NOTEBOOK_MODELS if args.quick else ALL_MODELS
    rows = []
    fitted = {}
    for name in candidates:
        est = build_model(name)
        est.fit(X_tr, y_tr)
        proba = est.predict_proba(X_te)[:, 1]
        pred = (proba >= 0.5).astype(int)
        metrics = metric_dict(y_te, pred, proba)
        metrics["model"] = name
        rows.append(metrics)
        fitted[name] = (est, proba)
        print(f"{name:22s}  acc={metrics['accuracy']:.4f}  auroc={metrics['auroc']:.4f}  f1={metrics['f1']:.4f}")

    comparison = pd.DataFrame(rows).set_index("model")
    comparison.to_csv(REPORTS_DIR / "deployable_holdout.csv")
    winner = comparison["auroc"].idxmax()
    estimator, proba = fitted[winner]
    if args.tune:
        from phishing.tuning import grouped_random_search

        print(f"Tuning {winner} under grouped CV...")
        search = grouped_random_search(winner, X_tr, y_tr, g_tr, n_iter=8)
        estimator = search.best_estimator_
        print(f"  best_params={search.best_params_}")
        estimator.fit(X_tr, y_tr)
        proba = estimator.predict_proba(X_te)[:, 1]

    from phishing.evaluate import calibrate

    print("Calibrating probabilities (isotonic)...")
    estimator = calibrate(estimator, X_tr, y_tr, method="isotonic", cv=3)
    proba = estimator.predict_proba(X_te)[:, 1]
    f1_thr, f1_val = best_f1_threshold(y_te, proba)
    fpr_thr, fpr_val = fpr_target_threshold(y_te, proba, max_fpr=0.01)
    f1_report = threshold_report(y_te, proba, f1_thr)
    print(f"\nWinner by AUROC: {winner}")
    print(f"  max-F1 threshold={f1_thr:.3f}  F1={f1_val:.4f}  acc={f1_report['accuracy']:.4f}")
    print(f"  1%-FPR threshold={fpr_thr:.3f}  achieved FPR={fpr_val:.4f}")
    print(f"  Brier={f1_report['brier']:.4f}")

    path = persist_model(
        estimator,
        feature_names=DEPLOYABLE_FEATURES,
        threshold=f1_thr,
        metrics=f1_report,
        model_name=winner,
        notes=(
            "25-feature deployable model (excludes Alexa/PageRank/Google Index/"
            "backlinks/2012 statistical reports). Trained on grouped holdout."
        ),
        extra={
            "fpr_threshold": fpr_thr,
            "grouped_holdout": comparison.loc[winner].to_dict(),
        },
        path=ARTIFACTS_DIR / "model.joblib",
    )
    print(f"Saved {path}")

    # Stage 2 reports from the same split, using the winner's algorithm on all 30.
    X_all, y_all, groups_all = load_xy()
    Xa_tr, Xa_te, ya_tr, ya_te, _, _ = grouped_split(X_all, y_all, groups_all)
    rf = build_model("Random Forest")
    tiers = tier_ablation(Xa_tr, ya_tr, Xa_te, ya_te, model_name="Random Forest")
    tiers.to_csv(REPORTS_DIR / "tier_ablation.csv")
    decay = decay_simulation(rf, Xa_tr, ya_tr, Xa_te, ya_te)
    decay.to_csv(REPORTS_DIR / "decay_simulation.csv")
    adv = adversarial_curve(rf, Xa_tr, ya_tr, Xa_te, ya_te, max_k=10)
    adv.to_csv(REPORTS_DIR / "adversarial_curve.csv")
    print("Wrote tier_ablation.csv, decay_simulation.csv, adversarial_curve.csv")

    from phishing.mining import (
        cluster_phishing,
        cluster_rule_crosstab,
        mine_rules,
        surrogate_tree,
    )

    print("Mining association rules and phishing clusters...")
    rules = mine_rules(Xa_tr, ya_tr)
    rules.to_csv(REPORTS_DIR / "association_rules.csv", index=False)
    labels, centroids = cluster_phishing(Xa_tr, ya_tr, n_clusters=3)
    centroids.to_csv(REPORTS_DIR / "phishing_clusters.csv")
    if not rules.empty:
        xtab = cluster_rule_crosstab(Xa_tr, labels, rules)
        xtab.to_csv(REPORTS_DIR / "cluster_rule_crosstab.csv", index=False)
    rf.fit(Xa_tr, ya_tr)
    y_hat = rf.predict(Xa_tr)
    _, tree_text = surrogate_tree(Xa_tr, y_hat, max_depth=3)
    (REPORTS_DIR / "surrogate_tree.txt").write_text(tree_text)
    print("Wrote association_rules.csv, phishing_clusters.csv, surrogate_tree.txt")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    from phishing.features.extractor import url_to_features
    from phishing.tuning import load_model

    model_path = Path(args.model) if args.model else ARTIFACTS_DIR / "model.joblib"
    if not model_path.exists():
        print(
            f"No trained model at {model_path}. Run: PYTHONPATH=src python -m phishing.cli train",
            file=sys.stderr,
        )
        return 1

    estimator, artifact = load_model(model_path)
    features, warnings = url_to_features(args.url, tier=args.tier)
    X = features[artifact.feature_names].to_frame().T
    proba = float(estimator.predict_proba(X)[:, 1][0])
    band = _risk_band(proba)
    pred = int(proba >= artifact.threshold)

    reasons = []
    try:
        from phishing.explain import shap_values, top_contributors

        _, values = shap_values(estimator, X, background=X)
        reasons = top_contributors(artifact.feature_names, values[0], features, k=5)
    except Exception as exc:  # noqa: BLE001
        reasons = [{"error": f"SHAP unavailable: {exc}"}]

    payload = {
        "url": args.url,
        "probability": round(proba, 4),
        "band": band,
        "prediction": "phishing" if pred else "legitimate",
        "threshold": artifact.threshold,
        "model": artifact.model_name,
        "tier": args.tier,
        "reasons": reasons,
        "warnings": [w.to_dict() for w in warnings],
        "features": features.to_dict(),
    }
    print(json.dumps(payload, indent=2))
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    """Compare live Tier-A features on known URLs against the 2012 legitimate class."""
    from phishing.data import load_raw, to_model_frame
    from phishing.features.url_features import extract_url_features
    from phishing.config import TIER_A, TARGET_COLUMN

    legit_urls = [
        "https://www.google.com/",
        "https://www.wikipedia.org/",
        "https://github.com/",
        "https://www.apple.com/",
        "https://www.microsoft.com/",
        "https://www.amazon.com/",
        "https://www.nytimes.com/",
        "https://www.bbc.com/",
        "https://www.mozilla.org/",
        "https://www.cloudflare.com/",
        "https://stackoverflow.com/",
        "https://www.reddit.com/",
        "https://www.linkedin.com/",
        "https://www.youtube.com/",
        "https://www.instagram.com/",
        "https://www.netflix.com/",
        "https://www.adobe.com/",
        "https://www.ibm.com/",
        "https://www.oracle.com/",
        "https://www.salesforce.com/",
    ]
    phishy_urls = [
        "http://192.168.1.10/login",
        "http://bit.ly/abc123",
        "http://paypal-secure-login.com/confirm",
        "http://www.bank.com@evil.example/steal",
        "http://https-www-paypal-it.soft-hair.com/",
        "http://login.secure.update.paypal.example.com/session",
        "http://example.com//http://phishing.example/drop",
        "http://tinyurl.com/r4nd0m",
        "http://confirm-account-appleid.com/webapps/mpp/home?dispatch=" + "a" * 80,
        "http://0x58.0xCC.0xCA.0x62/2/paypal.ca/index.html",
    ]

    rows = []
    for url, label in [(u, "legit_2026") for u in legit_urls] + [
        (u, "synthetic_phish") for u in phishy_urls
    ]:
        feats = extract_url_features(url)
        feats["source"] = label
        feats["url"] = url
        rows.append(feats)
    live = pd.DataFrame(rows)

    raw = to_model_frame(load_raw())
    legit_2012 = raw.loc[raw[TARGET_COLUMN] == 0, TIER_A]
    live_legit = live.loc[live["source"] == "legit_2026", TIER_A]

    comparison = pd.DataFrame(
        {
            "mean_2012_legit": legit_2012.mean(),
            "mean_2026_legit_tierA": live_legit.mean(),
            "mean_synthetic_phish_tierA": live.loc[
                live["source"] == "synthetic_phish", TIER_A
            ].mean(),
        }
    )
    _ensure_dirs()
    comparison.to_csv(REPORTS_DIR / "extractor_drift.csv")
    live.to_csv(REPORTS_DIR / "extractor_live_sample.csv", index=False)
    print(comparison.round(3).to_string())
    print(f"\nWrote {REPORTS_DIR / 'extractor_drift.csv'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="phishing")
    sub = p.add_subparsers(dest="cmd", required=True)

    ev = sub.add_parser("evaluate", help="random vs grouped CV leakage table")
    ev.add_argument("--quick", action="store_true", help="notebook's three models only")
    ev.set_defaults(func=cmd_evaluate)

    tr = sub.add_parser("train", help="train and persist the 25-feature model")
    tr.add_argument("--quick", action="store_true", help="skip XGBoost/LightGBM")
    tr.add_argument("--tune", action="store_true", help="RandomizedSearchCV on the winner")
    tr.set_defaults(func=cmd_train)

    sc = sub.add_parser("scan", help="extract features and score a URL")
    sc.add_argument("url")
    sc.add_argument("--tier", choices=["A", "B", "full"], default="full")
    sc.add_argument("--model", default=None)
    sc.set_defaults(func=cmd_scan)

    va = sub.add_parser("validate", help="Tier-A drift vs 2012 legitimate class")
    va.set_defaults(func=cmd_validate)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
