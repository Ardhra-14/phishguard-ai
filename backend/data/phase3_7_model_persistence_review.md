\# Phase 3.7 — Model Persistence Review



\*\*Status:\*\* Reviewed. Retraining and versioning are conscious "not doing this now" calls — see below.



\---



\## 1. Current persistence state (already fine)



The model is persisted correctly and loaded once at import time:



\- `backend/ml/models/xgboost\_phishing\_model.joblib` — the fitted `VotingClassifier` (RF + XGBoost, soft voting), loaded once in `Predictor.\_\_init\_\_`.

\- `backend/ml/models/xgboost\_phishing\_model.meta.json` — `feature\_columns\_in\_order` (54 cols), hyperparameters, `sanity\_check\_metrics`, `sanity\_check\_confusion\_matrix`.

\- `backend/data/preprocessing\_artifacts.json` — `sentinel\_value`, `tld`/`whois\_registrar` frequency maps, `ssl\_issuer\_top\_values`. Required at inference time to encode a new URL identically to how training data was encoded — `predictor.py` loads this alongside the model.



No action needed here; this was already sound going into Phase 3.7.



\## 2. Retraining on the full dataset — reviewed, \*\*not done this session\*\*



`meta.json` records:



```

"trained\_on": "80% stratified split of training\_features.csv (NOT full dataset)"

```



`data/training\_features.csv` has \*\*4,000 rows\*\* total. The shipped model was fit on \~3,200 (80%) and validated against the held-out 800 (20%), which is exactly where `sanity\_check\_metrics` (accuracy 0.959, ROC-AUC 0.990) and the confusion matrix (`\[\[383,17],\[16,384]]`) come from.



\*\*The trade-off, made explicit:\*\*

\- Training on the full 4,000 rows would give the shipped model \~25% more data, likely a small accuracy bump.

\- Doing so consumes the held-out test set — `sanity\_check\_metrics` would need to come from a fresh split (e.g. a new stratified holdout carved out \*before\* the final fit, or k-fold CV numbers) rather than "the" 20% currently baked into `meta.json`. Whichever approach is used, `meta.json`'s `sanity\_check\_metrics`/`sanity\_check\_confusion\_matrix` need regenerating to match, not left describing a split that no longer exists.

\- `scripts/train\_ensemble.py` exists and could rerun this, but re-fitting and reshipping the model that Phase 3.6 already verified against live scans (`google.com` → 0/SAFE, the `.tk` PayPal look-alike → 88/PHISHING) is a real, semi-irreversible change to what gets demoed — worth doing deliberately, not as a side effect of a test-writing session.



\*\*Recommendation:\*\* retrain on the full dataset before the CERT-In demo if there's time, using a fresh stratified holdout (e.g. 90/10) purely for the updated `sanity\_check\_metrics`, then regenerate `preprocessing\_artifacts.json` from the same full-data fit (see #3). Given it changes the actual shipped artifact, doing this as its own explicit step — not bundled into this test-writing pass — seemed like the safer call.



\## 3. `preprocessing\_artifacts.json` sync — reviewed, flagged for whenever retraining happens



The frequency-encoding maps (`tld`, `whois\_registrar`) and `ssl\_issuer\_top\_values` in `preprocessing\_artifacts.json` were computed from the \*current\* training split. If retraining happens on a different row set (e.g. the full 4,000), these need regenerating from the same data the model is refit on — `scripts/preprocess\_training\_data.py` presumably produces this file; rerun it alongside `train\_ensemble.py`, not independently, or `predictor.py`'s encoding silently drifts out of sync with what the model actually learned (frequencies would be off, and `ssl\_issuer\_top\_values`'s top-10 could change, quietly breaking the one-hot mapping).



\*\*Not done this session\*\* — bundled with the retraining decision in #2, since they're the same action.



\## 4. Model registry / versioning — reviewed, explicitly skipped



Considered a versioning/rollback scheme (e.g. `models/v1/`, `models/v2/`, a pointer file, or MLflow-style tracking) so a bad retrain can't silently replace a working demo model with no way back.



\*\*Not doing this for the hackathon timeline.\*\* A single committed `.joblib` + `.meta.json` pair is adequate for a SIH deadline where there's one shipped model at a time and `git log`/`git revert` already gives a rollback path if a retrain goes wrong. Worth reconsidering only if this moves toward the Phase 5 production deploy with multiple people retraining independently.



\---



\## Summary of what changed this session vs. what's deferred



| Item | This session | Deferred |

|---|---|---|

| `ml/predictor.py` real ensemble wiring | ✅ Reconstructed from Phase 3.6 spec (see file docstring) | |

| `scan.py` singleton usage | ✅ Fixed | |

| `\_persist\_scan` `features`/`shap` KeyError | ✅ Fixed (mapped to `features\_json`/`shap\_json`) | |

| `\_persist\_scan` `result\_data\["id"]` KeyError | ✅ Fixed (was `result\_data\["scan\_id"]`) | |

| `test\_phase3.py` | ✅ Written, 37/37 passing | |

| `closest\_brand` threading (open issue #2) | ✅ Fixed in `pipeline.py`, 39/39 passing | |

| Retrain on full 4,000-row dataset | | ⏳ Recommended before demo, not run this session |

| Regenerate `preprocessing\_artifacts.json` | | ⏳ Bundled with retraining above |

| Model registry/versioning | | ❌ Explicitly out of scope for hackathon timeline |