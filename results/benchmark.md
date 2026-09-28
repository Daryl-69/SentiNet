### Held-out simulated scenarios: 30 x 12 h, all attack types

30 captures, 21000 forecast windows (3388 with infiltration in the next 10 x 60 s windows).

| Model | Precision | Recall | F1 | FPR | ROC-AUC | PR-AUC | Brier | Onsets warned within K | Median lead (min) |
|---|---|---|---|---|---|---|---|---|---|
| **World model (ours)** | 0.846 | 0.885 | 0.865 | 0.031 | 0.974 | 0.899 | 0.043 | 13/22 (59%) | 14 |
| World model, history shuffled | 0.224 | 0.765 | 0.347 | 0.510 | 0.672 | 0.251 | 0.468 | - | - |
| Logistic regression (baseline, own F1-optimal threshold) | 0.435 | 0.577 | 0.496 | 0.144 | 0.788 | 0.560 | 0.167 | 18/22 (82%) | 1 |
| Logistic regression at the world model's FPR | 0.696 | 0.370 | 0.483 | 0.031 | 0.788 | 0.560 | 0.167 | 7/22 (32%) | 0 |

Stage detection macro-F1 (current window): 0.900. Stage forecast macro-F1: t+1 = 0.683, t+10 = 0.459.

### Unseen attack pattern: low-and-slow APT, model trained WITHOUT any slow-APT campaign (16 x 12 h)

16 captures, 11200 forecast windows (3427 with infiltration in the next 10 x 60 s windows).

| Model | Precision | Recall | F1 | FPR | ROC-AUC | PR-AUC | Brier | Onsets warned within K | Median lead (min) |
|---|---|---|---|---|---|---|---|---|---|
| **World model (ours)** | 0.929 | 0.335 | 0.492 | 0.011 | 0.791 | 0.725 | 0.185 | 0/16 (0%) | 0 |
| World model, history shuffled | 0.455 | 0.128 | 0.200 | 0.068 | 0.554 | 0.361 | 0.291 | - | - |
| Logistic regression (baseline, own F1-optimal threshold) | 0.449 | 0.167 | 0.243 | 0.090 | 0.582 | 0.397 | 0.231 | 6/16 (38%) | 0 |
| Logistic regression at the world model's FPR | 0.648 | 0.047 | 0.088 | 0.011 | 0.582 | 0.397 | 0.231 | 1/16 (6%) | 0 |

Stage detection macro-F1 (current window): 0.509. Stage forecast macro-F1: t+1 = 0.276, t+10 = 0.249.

### Same slow-APT test set, model that saw slow-APT campaigns in training (reference)

16 captures, 11200 forecast windows (3427 with infiltration in the next 10 x 60 s windows).

| Model | Precision | Recall | F1 | FPR | ROC-AUC | PR-AUC | Brier | Onsets warned within K | Median lead (min) |
|---|---|---|---|---|---|---|---|---|---|
| **World model (ours)** | 0.869 | 0.845 | 0.857 | 0.056 | 0.946 | 0.893 | 0.077 | 3/16 (19%) | 0 |
| World model, history shuffled | 0.331 | 0.525 | 0.406 | 0.468 | 0.538 | 0.319 | 0.447 | - | - |
| Logistic regression (baseline, own F1-optimal threshold) | 0.446 | 0.257 | 0.326 | 0.141 | 0.593 | 0.431 | 0.220 | 8/16 (50%) | 2 |
| Logistic regression at the world model's FPR | 0.561 | 0.162 | 0.251 | 0.056 | 0.593 | 0.431 | 0.220 | 5/16 (31%) | 0 |

Stage detection macro-F1 (current window): 0.623. Stage forecast macro-F1: t+1 = 0.315, t+10 = 0.296.
