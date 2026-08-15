# Phishing URL Analysis

Extends a DATS 2103 coursework project on the UCI Phishing Websites dataset into a leakage-corrected ML pipeline and a live URL feature extractor that a trained model can score.

The original submission is unchanged: [`Choi_Final.ipynb`](Choi_Final.ipynb), [`Choi_Final_Write_Up.pdf`](Choi_Final_Write_Up.pdf), and [`Phishing Websites Features.docx`](Phishing%20Websites%20Features.docx) (the authors' extraction spec). Everything under `src/`, `tests/`, `notebooks/`, and `reports/` is new.

## The dataset

[`Training_Dataset.csv`](Training_Dataset.csv) is the [UCI Phishing Websites](https://archive.ics.uci.edu/dataset/327/phishing+websites) set (Mohammad, Thabtah & McCluskey, 2012):

- 11,055 rows, 30 integer features, binary label
- Features encoded as `-1` (phishing indicator), `0` (suspicious), `1` (legitimate)
- Original `Result`: `-1` phishing / `1` legitimate. We recode so **1 = phishing** (the positive class)
- 55.7% legitimate / 44.3% phishing
- No missing values
- 5,785 unique feature patterns; 5,206 exact duplicate rows (47.1%); 64 patterns with conflicting labels (~1% irreducible error)

The 30 features fall into three extraction-cost tiers:

| Tier | Count | What it takes | Examples |
|---|---|---|---|
| A — URL string | 8 | parse the URL, no network | IP-in-host, length, `@`, dash in domain, shorteners |
| B — page content | 11 | fetch HTML, never execute JS | anchor destinations, SFH, iframe, mailto |
| C — infrastructure | 6 | TLS handshake, WHOIS, DNS | `SSLfinal_State`, domain age, registration length |
| Unobtainable in 2026 | 5 | retired APIs / 2012 blocklists | Alexa `web_traffic`, toolbar `Page_Rank`, Google Index, inbound-link counts, PhishTank-2012 stats |

## Original coursework findings

Random Forest (300 trees, defaults) reached **97.69% test accuracy / 0.9966 AUROC** on a random 80/20 split, ahead of Gradient Boosting (95.66%) and Logistic Regression (~92%). `SSLfinal_State` and `URL_of_Anchor` dominated importance. The write-up already flagged that duplicate patterns leak across random folds, but did not correct for it.

## What we built (stages 0–4)

### Stage 0 — Foundation

`.gitignore`, pinned `requirements.txt`, and an importable `src/phishing` package. `data.py` loads the CSV, recodes the label, and hashes each 30-feature row into a **pattern-group id**. Tests lock the notebook's EDA numbers: shape `(11055, 31)`, 5,785 unique patterns, 64 conflicts, phishing rate 0.443.

### Stage 1 — Honest baseline

Five classifiers (the original trio plus XGBoost and LightGBM), evaluated under both `StratifiedKFold` and `StratifiedGroupKFold` on those pattern ids. The **test split is grouped too**.

5-fold CV, same seed 42:

| Model | Random accuracy | Grouped accuracy | Optimism |
|---|---|---|---|
| Logistic Regression | 0.9273 | 0.9262 | +0.0010 |
| Gradient Boosting | 0.9513 | 0.9470 | +0.0044 |
| XGBoost | 0.9667 | 0.9550 | +0.0117 |
| Random Forest | 0.9708 | 0.9548 | +0.0160 |
| LightGBM | 0.9730 | **0.9559** | +0.0171 |

The leak inflates tree ensembles by 1–2 accuracy points and barely moves logistic regression, which cannot memorise individual patterns. Under grouped CV the ranking also changes: LightGBM edges Random Forest, which had looked like the clear winner in the original notebook.

On a grouped holdout of the **25 deployable features**, LightGBM wins on AUROC (0.987). After grouped `RandomizedSearchCV` and isotonic calibration:

- max-F1 threshold **0.38** → accuracy 0.948, F1 0.941
- 1%-FPR operating point **0.938** → achieved FPR 0.0088
- Brier score 0.044

That threshold search is the fix for the write-up's observation that Gradient Boosting's AUROC nearly matched Random Forest while accuracy trailed by two points: it was a default-0.5 cut problem, not a ranking problem.

### Stage 2 — Feature economics and decay

Random Forest, grouped holdout, all 30 features unless noted:

| Feature set | Features | Accuracy | AUROC |
|---|---|---|---|
| A — URL string only | 8 | 0.724 | 0.804 |
| A + B — URL + HTML | 19 | 0.893 | 0.961 |
| A + B + C — deployable | 25 | 0.940 | 0.971 |
| All 30 | 30 | 0.950 | 0.989 |

URL-only is not close to enough. Fetching the page buys most of the remaining accuracy; the five dead reputation features are worth about one extra point if you retrain without them (0.941).

Decay on a model trained in 2012 conditions:

| Scenario | Accuracy | Recall |
|---|---|---|
| Original 2012 test distribution | 0.950 | 0.950 |
| Force `SSLfinal_State = 1` (universal HTTPS) | 0.894 | **0.784** |
| Neutralize Alexa / PageRank | 0.895 | 0.961 |
| Both | 0.869 | 0.840 |

HTTPS-by-default costs more than losing Alexa. Recall falling to 0.78 when every site "has SSL" is the quantitative version of "this 2012 model aged".

Adversarial cheapest-k flips on phishing rows: flipping the two cheapest features (`having_At_Symbol`, `Prefix_Suffix`) drops recall from 0.95 to **0.57**. A dash in the domain name is free for an attacker to remove and, in this feature set, devastating to leave in.

The scanner therefore loads a **25-feature** model that was never trained on the five unobtainable columns.

### Stage 3 — Unsupervised analysis

FP-Growth over one-hot items such as `SSLfinal_State=-1`. Top rule:

> `SSLfinal_State=-1 AND URL_of_Anchor=-1 → phishing`  
> support 0.186, **confidence 1.0**, lift 2.25

Many high-lift rules are `URL_of_Anchor=-1` conjoined with one other indicator — the same feature the supervised models ranked second. k-modes on the phishing subset yields three large clusters (1,785 / 1,246 / 885 rows) that share weak SSL and off-domain anchors and differ on IP-in-URL and subdomain depth. A depth-3 surrogate tree fitted on Random Forest predictions recovers the same spine: `SSLfinal_State` then `URL_of_Anchor`, then `Links_in_tags` / `Prefix_Suffix`.

### Stage 4 — Live extractor

`url_to_features(url, tier="A"|"B"|"full")` implements the docx rules (URL length 54/75, anchor 31%/67%, request-URL 22%, links-in-tags 17%/81%, cert age ≥ 1 year, domain age ≥ 6 months, the port table). Failures never raise: the feature is filled with 0 and a warning is recorded. `Redirect` follows the CSV's `{0, 1}` encoding, not the paper's three-valued rule.

Tier-A drift check (20 well-known legitimate sites vs 10 synthetic phishing-shaped URLs vs the 2012 legitimate class):

- 2026 legitimate URLs are uniformly `+1` on every string feature (no `@`, no IP host, no dash, no shortener).
- 2012 "legitimate" rows were much messier (e.g. mean `URL_Length` −0.59, mean `Prefix_Suffix` −0.52).
- Synthetic phishing URLs still light up IP hosts, shorteners, and dashes.

That gap is 2012-vs-2026 drift in the *inputs*, not just in HTTPS. A model trained on 2012 legitimate URLs has never seen how clean modern legitimate URLs look.

`scan` returns probability, risk band, SHAP contributors, and warnings. Example:

```text
PYTHONPATH=src python -m phishing.cli scan --tier A \
  http://paypal-secure-login.com/confirm
# probability 0.83, band critical, prediction phishing
# top SHAP: SSLfinal_State (filled 0 / suspicious because tier A skipped TLS)
```

## How machine learning plays into this project

Phishing detection here is supervised binary classification on a fixed, already-discretized feature space. That is why classical tabular models are the right tool: there is no raw HTML to embed and no sequence to tokenize until Stage 4 builds an extractor, and even then the extractor's job is to land in the same 30-dimensional encoding the 2012 paper defined.

**A linear baseline exists so the ensembles have something to beat.** Logistic regression with effectively no penalty recovers the ISLP Chapter 4 model and stays within 0.1 points when leakage is removed. Tree ensembles pick up non-additive structure the linear model cannot represent without hand-built interactions — the association rules and the surrogate tree both say the signal is `SSLfinal_State` *and* `URL_of_Anchor`, not either one alone. That is the 3-point gap.

**Evaluation protocol is part of the model.** Duplicate feature vectors mean a random split scores memorisation. Grouped CV does not make the models worse; it makes the *number* honest. Capacity tracks the optimism: logistic +0.1 pp, boosting +0.4, forests and GBMs +1.2 to +1.7. Publishing the 97.69% figure without that table would have been the leak.

**Probabilities are the product, not labels.** A scanner that returns "phishing" at a hardcoded 0.5 cut throws away the ROC. Isotonic calibration plus a searched threshold (max-F1 for a balanced demo, 1% FPR for a conservative gateway) is what turns AUROC into an operating point a person can use. Brier score is the metric that tells you whether that probability is a frequency.

**Explainability is how the model earns the right to block a URL.** SHAP on the unwrapped tree model attributes a live score to individual encoded features. Combined with Stage 3's human-readable rules, the output is "this looks like phishing because the certificate state is weak and the anchors point off-domain", not a bare 0.83.

**Unsupervised mining is not a competing classifier.** It is a check that the supervised story is not an artifact of one algorithm. When FP-Growth, k-modes, a depth-3 surrogate, Gini importance, and logistic coefficients all surface the same two features, the finding is about the data.

**Feature decay is a maintenance commitment.** `SSLfinal_State` was 32% of Random Forest importance and 71% of Gradient Boosting's in 2012. Let's Encrypt made that feature cheap to fake. Retraining without dead reputation columns, simulating universal HTTPS, and refusing to feed a 30-feature model constant placeholders it never saw in training are all ML decisions: they are about the support of the training distribution, not about software packaging. A deployed phishing model is a living estimator. The 2012 snapshot is the prior.

## Quickstart

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .              # makes `phishing` importable everywhere

# lock the EDA numbers, URL/HTML extractors, and ML helpers
pytest -m "not network"

# leakage-delta table → reports/leakage_delta.csv
phishing evaluate

# train the 25-feature model, write Stage 2–3 reports, save artifacts/model.joblib
phishing train --tune

# score a URL (tier A is offline; B fetches HTML; full adds TLS/WHOIS/DNS)
phishing scan --tier A https://example.com
# equivalent: python run.py scan --tier A https://example.com

# Tier-A drift vs the 2012 legitimate class
phishing validate
```

Research scripts write their tables and figures to `reports/`, and the model the
API serves to `artifacts/model.joblib`:

```bash
python analysis/01_grouped_evaluation.py     # leakage: random vs grouped split
python analysis/02_calibration_thresholds.py # Brier, Platt, cost-optimal cutoffs
python analysis/03_shap_explanations.py      # SHAP vs Gini, encoding audit
python analysis/04_obsolescence.py           # accuracy under 2026 feature loss
python analysis/05_minimal_features.py       # greedy forward selection (slow)
python analysis/06_train_final.py            # persist artifacts/model.joblib
```

### Local website

The scanner UI is not hosted anywhere. After the venv is active and `artifacts/model.joblib` exists (`phishing train --tune` if you have not trained yet):

```bash
PYTHONPATH=src uvicorn api.main:app --reload --port 8000
```

If you ran `pip install -e .`, you can drop `PYTHONPATH=src`. Then open [http://127.0.0.1:8000](http://127.0.0.1:8000) in a browser. You should see **Phishing URL Scanner** with a URL field and a **Research findings** tab. Opening `web/index.html` as a file will not work: the page talks to `/api/scan` on this server.

Narrative notebooks that import the same package: [`notebooks/01_honest_baseline.ipynb`](notebooks/01_honest_baseline.ipynb), [`notebooks/02_feature_decay.ipynb`](notebooks/02_feature_decay.ipynb), [`notebooks/03_rule_mining.ipynb`](notebooks/03_rule_mining.ipynb).

## Repo map

```text
Training_Dataset.csv          UCI 2012 table
Choi_Final.ipynb              original coursework (untouched)
src/phishing/
  config.py                   feature order, tiers, seeds
  data.py                     load, recode, pattern groups, grouped split
  models.py                   LogReg / RF / GB / XGBoost / LightGBM
  evaluate.py                 grouped CV, thresholds, calibration
  tuning.py                   RandomizedSearchCV, persist/load
  decay.py                    tier ablation, HTTPS decay, adversarial flips
  explain.py                  SHAP
  mining.py                   FP-Growth, k-modes, surrogate tree
  cli.py                      evaluate | train | scan | validate
  io.py                       JSON writers shared by the analysis scripts
  scanner.py                  live scan → verdict, SHAP signals, coverage
  features/                   live extractor (fetch, URL, HTML, TLS/WHOIS)
analysis/                     numbered research scripts → reports/
api/main.py                   FastAPI service (scan, model, findings, health)
web/                          vanilla JS scanner UI served by the API
tests/                        pytest, network tests marked skippable
notebooks/                    stages 1–3 narrative
reports/                      CSV / JSON / figures from the analysis scripts
artifacts/model.joblib        fitted 25-feature model (gitignored; run train)
```

## Limitations

- Training data is from **2012**. Phishing kits, HTTPS prevalence, and URL fashion have all moved.
- 64 conflicting-label patterns set an accuracy ceiling near 99% even in-sample.
- Five original features cannot be reproduced; the scanner warns and the deployable model was trained without them.
- `SSLfinal_State` for live URLs uses a modern CA list (Let's Encrypt, DigiCert, …) on top of the 2012 names. That is the honest 2026 measurement, and it is *not* the same random variable the 2012 labels were built from.
- Page fetches do not execute JavaScript, so `on_mouseover` / `RightClick` / `popUpWidnow` are source-text approximations.
- Grouped CV is still i.i.d. across *patterns*, not across time. There is no temporal holdout in this dataset.

## References

Mohammad, R. M., Thabtah, F., & McCluskey, L. (2012). An Assessment of Features Related to Phishing Websites Using an Automated Technique. *ICITST*, 492–497.

UCI Machine Learning Repository: Phishing Websites Dataset. https://archive.ics.uci.edu/dataset/327/phishing+websites
