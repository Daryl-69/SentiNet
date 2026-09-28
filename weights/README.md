# Trained weights

| File | What |
|---|---|
| `world_model.pt` | World model (PyTorch state dict + architecture config), about 170k parameters |
| `meta.json` | Training config (window, horizon K, context, model sizes, epochs, seed), the feature normaliser, the validation-chosen alarm thresholds and the training history |
| `baselines.joblib` | Logistic-regression baseline (same features, same target) and the Isolation-Forest flow scorer |

**Trained on:** 48 simulated 12-hour enterprise scenarios (`python -m sentinet generate --scenarios 48 --seed 0`).
About 20% of the scenarios were held out for validation, early stopping and threshold selection. The public
datasets could not be downloaded in the build environment, so these weights have not seen real traffic. Retrain on
your own data or on a public dataset:

```bash
python -m sentinet generate -o data/synthetic --scenarios 48 --seed 0     # reproduces the training data
python -m sentinet train -d data/synthetic -o weights                     # ~10 min on a 4-core CPU
python -m sentinet train -d path/to/CIC-IDS2017/TrafficLabelling -o weights_cic
```

Then point the tools at the new folder: `python -m sentinet forecast --weights weights_cic ...`. For the app, replace
the files in this folder.
