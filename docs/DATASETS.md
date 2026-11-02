# Dataset sources

Raw datasets are gitignored (large, redistributable from their original
sources) — only the trained model bundles (`models/*.joblib`) are
committed. To retrain from scratch, download these into `data/raw/`
under the exact filenames below (each trainer in `ml/` expects them):

| File | Source | Used by |
|---|---|---|
| `data/raw/nsl_kdd_train.csv`<br>`data/raw/nsl_kdd_test.csv` | [Mamcose/NSL-KDD-Network-Intrusion-Detection](https://github.com/Mamcose/NSL-KDD-Network-Intrusion-Detection) — the standard NSL-KDD benchmark (`KDDTrain+.txt`/`KDDTest+.txt`, no header row) | `ml/network_ids/train.py` |
| `data/raw/malicious_urls_raw.csv` | [faizann24/Using-machine-learning-to-detect-malicious-URLs](https://github.com/faizann24/Using-machine-learning-to-detect-malicious-URLs) — `data/data.csv` (420k labeled URLs, columns `url,label`) | `ml/phishing/train.py` |
| `data/raw/clamp_integrated.csv` | [urwithajit9/ClaMP](https://github.com/urwithajit9/ClaMP) — `Dataset/ClaMP_Integrated-5184.csv` (static PE-header features) | `ml/malware/train.py` |

All three are public, academic/benchmark datasets — no real victims'
data, no real malware binaries (ClaMP ships pre-extracted numeric
header features, never the executables themselves). See
[`ETHICS.md`](ETHICS.md).

Once the files are in place: `python ml/<module>/train.py` for each
module writes `models/<module>.joblib` + `models/<module>_metrics.json`.
