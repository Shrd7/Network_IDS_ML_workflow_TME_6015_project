#!/usr/bin/env python3
"""Sanity check of the window dataset.

1. Class counts (main vs heldout)
2. Constant or near-constant features (the old 'only 3 useful features' problem)
3. Quick Random Forest baseline:
   - GroupKFold on 'main', grouped by run (no run in both train and test)
   - Train on all 'main', test on 'heldout' (unseen tree topology)
Works on dataset/windows_2s.csv and dataset/flows.csv:
   python3 check_dataset.py dataset/flows.csv
"""
import sys

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.model_selection import GroupKFold

META = ["session_id", "window_start", "server_ip", "topology", "split_group",
        "attack_pkts", "attack_frac", "label",
        # identifiers in CICFlowMeter output (never model inputs)
        "src_ip", "dst_ip", "src_port", "dst_port", "src_mac", "dst_mac", "timestamp",
        "flow_id", "protocol"]

path = sys.argv[1] if len(sys.argv) > 1 else "dataset/windows_2s.csv"
df = pd.read_csv(path)
feats = [c for c in df.columns if c not in META and pd.api.types.is_numeric_dtype(df[c])]
df[feats] = df[feats].replace([np.inf, -np.inf], np.nan).fillna(0)

print("== Class counts ==")
print(df.groupby(["label", "split_group"]).size().unstack(fill_value=0), "\n")

print("== Features with (almost) one value ==")
weak = [c for c in feats if df[c].nunique() <= 1 or df[c].value_counts(normalize=True).iloc[0] > 0.99]
print(weak if weak else "none", f"\n({len(feats) - len(weak)} of {len(feats)} features vary)\n")

main, held = df[df.split_group == "main"], df[df.split_group == "heldout"]
rf = lambda: RandomForestClassifier(n_estimators=200, class_weight="balanced",
                                    n_jobs=-1, random_state=0)

k = min(5, main.session_id.nunique())
if k >= 2:
    scores = []
    for tr, te in GroupKFold(k).split(main, groups=main.session_id):
        m = rf().fit(main.iloc[tr][feats], main.iloc[tr].label)
        scores.append(f1_score(main.iloc[te].label, m.predict(main.iloc[te][feats]), average="macro"))
    print(f"== {k}-fold GroupKFold macro-F1 (main): {np.mean(scores):.3f} +/- {np.std(scores):.3f}\n")

m = rf().fit(main[feats], main.label)
if len(held):
    pred = m.predict(held[feats])
    print("== Held-out (tree topology) ==")
    print(classification_report(held.label, pred, digits=3))
    labels = sorted(df.label.unique())
    print(pd.DataFrame(confusion_matrix(held.label, pred, labels=labels), index=labels, columns=labels))

print("\n== Top 15 features ==")
print(pd.Series(m.feature_importances_, index=feats).sort_values(ascending=False).head(15))
