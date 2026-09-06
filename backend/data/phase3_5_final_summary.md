## Third bug found this session: mislabeled baseline script

`scripts/train_xgboost_baseline.py` — meant to hold the plain, untuned
XGBoost baseline (Step 1) — was discovered to actually contain
`tune_xgboost.py`'s RandomizedSearchCV tuning logic (Step 3), mislabeled
under the Step 1 filename and docstring. This predates this session; found
incidentally during the dataset/model rebuild, unrelated to the
path_length investigation.

**Implication**: any historical report that cited XGBoost-untuned numbers
from this file was actually reporting tuned numbers under the "untuned"
label. `tune_xgboost.py` itself was untouched and unaffected — only the
duplicate/misnamed copy was wrong.

**Fix**: reconstructed `train_xgboost_baseline.py` this session from
`tune_xgboost.py`'s data-loading/eval/report-writing scaffolding, with the
search wrapper removed and a single plain `XGBClassifier` fit in its
place. Current `phase3_4_baseline_results.md` reflects the corrected
script. Historical pre-session baseline numbers should not be trusted.