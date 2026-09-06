\# PhishGuard AI — Project Handoff (Phase 0–3.5 Complete, Phase 3.6 Up Next)



\*\*Project:\*\* PhishGuard AI — AI-powered phishing domain detection system for NTRO/CERT-In (SIH 1454)

\*\*Stack:\*\* FastAPI + Python 3.12 + PostgreSQL + Redis + XGBoost + RandomForest (soft-voting ensemble) + SHAP

\*\*Repo:\*\* `https://github.com/Ardhra-14/phishguard-ai`

\*\*Local path:\*\* `C:\\Users\\arudh\\OneDrive\\Pictures\\Desktop\\phishguard\_phase0`

\*\*Dev environment:\*\* Windows, Docker Desktop (WSL2 backend), PowerShell

\*\*Docker Compose service name:\*\* `api` (NOT `backend`), container names `phishguard\_api`, `phishguard\_db`, `phishguard\_redis`



\---



\## Current Status



| Phase | Status | Notes |

|---|---|---|

| Phase 0 — FastAPI skeleton, DB models, middleware | ✅ Complete | |

| Phase 1 — Lexical/brand/TLD/IDN feature extraction | ✅ Complete | 25/25 tests passing (pre-dates the `path\_length` fix below — re-run if in doubt) |

| Phase 2 — DNS resolver, WHOIS, SSL inspector | ✅ Complete | 44/44 tests passing |

| Phase 3.0 — Pipeline fix (prep) | ✅ Complete | |

| Phase 3.1 — Training dataset acquisition | ✅ Complete | Rebuilt twice more this session — see "Phase 3.1 fix v2" below |

| Phase 3.2 — Preprocessing / feature engineering | ✅ Complete | Re-run 3x this session, current output reflects the final rebuild |

| Phase 3.3 — Random Forest baseline | ✅ Complete | See results below (numbers changed from original report — see note) |

| Phase 3.4 — XGBoost + tuning + ensemble | ✅ Complete | \*\*Final model is now the RF+XGBoost ensemble\*\*, not tuned XGBoost alone — decision changed this session, see below |

| \*\*Phase 3.5 — SHAP explainability\*\* | ✅ \*\*Complete\*\* | See `phase3\_5\_final\_summary.md` for full detail |

| Phase 3.6 — `ml/predictor.py` (wire into `scan.py`) | ⏳ \*\*NEXT UP\*\* | Not started. Local-explainability function is ready to call — see "What Phase 3.6 needs" below |

| Phase 3.7 — Model persistence + `test\_phase3.py` | ⏳ Not started | |

| Phase 4 — Playwright screenshot + pHash + DOM fingerprinting | ⏳ Not started | |

| Phase 5 — CERT-In PDF report + React frontend + prod deploy | ⏳ Not started | |



\---



\## IMPORTANT — read before touching anything



\*\*Three real bugs were found and fixed this session, one of which is a live production code bug, not just a training-data issue:\*\*



1\. \*\*`features/url\_features.py`\*\* — `path\_length` was computed as raw `len(parsed.path)`, so a trailing slash (`https://x.com/` vs `https://x.com`) silently added +1 to an otherwise-identical bare-homepage URL. This is used by `FeaturePipeline` for \*\*real, live scans\*\*, not just training data — if any other part of the codebase (a test, a cached value, a previous model version) assumes the old `path\_length` semantics, it will be inconsistent with the current model. Fixed by stripping a single trailing `/` before measuring length.



2\. \*\*`scripts/build\_training\_dataset.py`\*\* — the legit-URL fetch logic (`\_resolve\_real\_url`) had no `User-Agent` header, didn't check HTTP status codes, used a short timeout with no retry, and didn't try a `www.` fallback on connection failure. All fixed. This one is training-data-collection-only, not production code.



3\. \*\*`scripts/train\_xgboost\_baseline.py`\*\* — was found to actually contain `tune\_xgboost.py`'s tuning logic under the wrong filename (predates this session, unrelated to the two bugs above). Reconstructed this session as a genuine untuned baseline. See `phase3\_5\_final\_summary.md` for detail.



Fixes 1 and 2 are fully explained, with root-cause investigation, in `phase3\_5\_path\_length\_check.md` and the "IMPORTANT v2" note now in `build\_training\_dataset.py`'s own docstring. Fix 3 is explained in `phase3\_5\_final\_summary.md`'s "Third bug found this session" section.



\*\*If you're picking this up fresh: `git log` / `git diff` to see exactly what changed in `features/url\_features.py`, `scripts/build\_training\_dataset.py`, and `scripts/train\_xgboost\_baseline.py` this session before assuming anything about prior behavior.\*\*



\---



\## Phase 3.1 fix v2 (this session)



Beyond the original Phase 3.1 fix (documented in the prior handoff — the `fetch\_legit\_urls()` rewrite that stopped emitting 100% bare-domain legit URLs), a second, deeper investigation this session found:



\- \*\*\~68% of the legit class was still at `path\_length` 0-or-1\*\* even after the original fix, traced to: no `User-Agent` (bot-blocked responses silently accepted as "genuine" bare fetches), a fallback template list that picked "bare" too often, a timeout/concurrency combination causing avoidable transient failures, and untried `www.` fallback for apex-only domains. Fixed — see `scripts/diagnose\_legit\_fetch.py` for the diagnostic tooling used (kept in the repo, useful if this class of issue recurs).

\- \*\*The deeper bug\*\*: even after that fix, SHAP analysis kept surfacing `path\_length` as suspiciously dominant. Root cause turned out to be the `url\_features.py` trailing-slash bug described above — not a data-collection issue at all, but a feature-extraction bug affecting every URL ever scored by the pipeline (training or live). Fixed.



\*\*Dataset was rebuilt three times this session\*\* (fetch-logic fix → verify → discover the deeper bug → fix `url\_features.py` → rebuild again). The current `training\_dataset.csv` / `training\_features.csv` / `preprocessing\_artifacts.json` reflect the final, fully-fixed pipeline. If you ever need to rebuild again:

```powershell

Remove-Item backend\\data\\training\_dataset.csv

docker compose exec api python scripts/build\_training\_dataset.py

docker compose exec api python scripts/analyze\_training\_dataset.py

docker compose exec api python scripts/preprocess\_training\_data.py

```



\---



\## Phase 3.3 — Random Forest Baseline (Complete, rebuilt)



\*\*Current results (test set, n=800, post both fixes):\*\*



| Metric | Value |

|---|---|

| accuracy | 0.9537 |

| precision | 0.9504 |

| recall | 0.9575 |

| f1 | 0.9539 |

| roc\_auc | 0.9888 |



Confusion matrix: `\[\[380, 20], \[17, 383]]`.



\*\*Note the drop from the original report (was \~0.9712 accuracy).\*\* This is expected and correct — some of the original accuracy was the model exploiting the now-fixed `path\_length` artifact, not genuine signal. These are the trustworthy numbers.



Top features: `url\_length`, `entropy`, `whois\_domain\_age\_days`, `has\_https`, `aggregate\_lexical\_risk\_score`, `subdomain\_depth`, `path\_length` (now a modest #7, no longer inflated).



\---



\## Phase 3.4 — XGBoost + Tuning + Ensemble (Complete, rebuilt — DECISION CHANGED)



\*\*Current results (test set, n=800, post both fixes):\*\*



| Model | accuracy | precision | recall | f1 | roc\_auc |

|---|---|---|---|---|---|

| RF baseline (3.3) | 0.9537 | 0.9504 | 0.9575 | 0.9539 | 0.9888 |

| XGBoost untuned | 0.9538 | 0.9481 | 0.9600 | 0.9540 | 0.9917 |

| XGBoost tuned | 0.9550 | 0.9550 | 0.9550 | 0.9550 | 0.9896 |

| \*\*RF+XGB ensemble (soft voting)\*\* | \*\*0.9588\*\* | \*\*0.9576\*\* | 0.9600 | \*\*0.9588\*\* | 0.9900 |



\*\*Best XGBoost hyperparameters\*\* (from `RandomizedSearchCV`, reproduced identically across two of the three rebuilds this session — same `random\_state=42` seeding the candidate search):

```json

{

&#x20; "colsample\_bytree": 0.7043574493366855,

&#x20; "gamma": 0.07652270145192375,

&#x20; "learning\_rate": 0.28069652934305006,

&#x20; "max\_depth": 9,

&#x20; "min\_child\_weight": 1,

&#x20; "n\_estimators": 424,

&#x20; "reg\_alpha": 1.3679275387962821,

&#x20; "reg\_lambda": 2.655479075364698,

&#x20; "subsample": 0.9775566418243029

}

```



\*\*Ensemble decision — CHANGED this session.\*\* In the original Phase 3.4 run and the first rebuild cycle, the ensemble tied tuned XGBoost exactly on every metric, so tuned XGBoost alone was kept (per the "only adopt if it beats the better single model" rule). \*\*After the second fix (the `url\_features.py` bug), the ensemble now beats every individual model simultaneously\*\* on accuracy/precision/f1, with the most balanced confusion matrix of the four. The gain is modest (\~0.4pp, roughly one standard error on an 800-row test set) but consistent across multiple metrics rather than a single-metric artifact. \*\*Ensemble adopted — this is the model going into Phase 3.6.\*\*



\*\*Model persisted:\*\*

\- `backend/ml/models/xgboost\_phishing\_model.joblib` — \*\*now a fitted `VotingClassifier`\*\* (RF + XGBoost, soft voting), not a bare `XGBClassifier`. Filename kept as-is for path compatibility, but check `meta.json`'s `model\_type` field before assuming what's inside.

\- `backend/ml/models/xgboost\_phishing\_model.meta.json` — component hyperparameters (both RF and XGBoost), exact feature column order, sanity-check metrics, `ensemble\_adoption\_note` explaining the decision history, and a note that `data/preprocessing\_artifacts.json` is required at inference time.



\*\*Design choice still open for Phase 3.6/3.7 (unchanged from original handoff):\*\* the persisted model was trained on the same 80% split used for evaluation, not the full 4000-row dataset. Whether to retrain on the full dataset before production shipping is still an open decision.



\---



\## Phase 3.5 — SHAP Explainability (Complete)



Full detail in `backend/data/phase3\_5\_final\_summary.md`. Summary:



\- \*\*Global explainability\*\*: `scripts/explain\_shap\_global\_ensemble.py`. Component-wise (RF + XGBoost explained separately via `TreeExplainer`, `tree\_path\_dependent`, no background dataset needed) — NOT a single combined SHAP value, since the two models' raw outputs live in different spaces (RF: probability, XGBoost: margin/log-odds) and combining them would be mathematically invalid. Reports in `phase3\_5\_shap\_global\_results.md`.



\- \*\*Local (per-prediction) explainability — what Phase 3.6 needs:\*\*

&#x20; `scripts/explain\_single\_url.py` exposes two functions:

&#x20; - `build\_explainers(model) -> (rf\_explainer, xgb\_explainer)` — call \*\*once\*\*, e.g. at API startup. Cheap, no background dataset to load.

&#x20; - `explain\_single\_row(row\_df, rf\_explainer, xgb\_explainer, feature\_order, top\_n=8) -> dict` — call \*\*per scanned URL\*\*. Returns top contributing features (with signed SHAP values and feature values) for both the RF component (probability space) and XGBoost component (margin space), plus each component's base value.



&#x20; Demonstrated against 3 example rows (highest-confidence phishing, highest-confidence legit, boundary case) in `phase3\_5\_local\_explainability\_examples.md` — all outputs directionally sane, no red flags. \*\*This is the function to wire into `scan.py`.\*\*



\- \*\*The `path\_length` investigation\*\* (see "IMPORTANT" section above and `phase3\_5\_path\_length\_check.md` for full detail) consumed most of this phase's actual time but resulted in two real bug fixes, one of which (the `url\_features.py` fix) is a genuine production-code correctness fix, not just a Phase 3.5 side-quest.



\- \*\*A third, unrelated bug\*\* (`train\_xgboost\_baseline.py` mislabeling) was also discovered and fixed incidentally during this phase's rebuild — see "IMPORTANT" section above and `phase3\_5\_final\_summary.md`.



\---



\## What's Next — Phase 3.6: `ml/predictor.py`, wire into `scan.py`



Starting point:

\- `backend/ml/models/xgboost\_phishing\_model.joblib` — the persisted RF+XGBoost ensemble

\- `backend/ml/models/xgboost\_phishing\_model.meta.json` — feature order, component hyperparameters, ensemble adoption note

\- `backend/data/preprocessing\_artifacts.json` — required to encode a single incoming URL identically to training

\- `backend/scripts/explain\_single\_url.py` — the local-explainability functions to reuse (don't rebuild this logic in `predictor.py`; import and call it)



Known open decisions carried over from the original handoff (still not made):

1\. Whether to retrain the final model on the full 4000-row dataset (not just the 80% split) before shipping.

2\. Where explainability output surfaces in the API response shape — presumably alongside the phishing/legit prediction, but the exact JSON contract with the frontend isn't decided yet.



New from this session:

3\. `predictor.py` needs to call `model.predict\_proba()` on a `VotingClassifier`, not `XGBClassifier` directly — should work identically via sklearn's standard interface, but worth a quick sanity check given the model type changed mid-project.

4\. Add `matplotlib` and `shap` to `backend/requirements.txt` if not already done — needed for anything that reuses the Phase 3.5 explainability scripts.



\*\*Please pick up from here — start Phase 3.6, broken into small reviewable steps like we've been doing.\*\*



\*End of handoff. Paste this into a new chat to continue with Phase 3.6.\*

