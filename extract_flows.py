#!/usr/bin/env python3
"""Turn every out/<run>/capture.pcap into CIC-IDS2017-style flows, label them, and merge
them into dataset/flows.csv.

Label rule: each attacker host runs only one attack type and sends nothing else.
A flow touching attacker IP X gets X's class. All other flows are benign.
Flows with an IP that is not in the run (should not happen) are dropped.
"""
import argparse
import glob
import json
import os

import dpkt
import pandas as pd

from flowfeat import FEATURES, META, FlowTable

ap = argparse.ArgumentParser()
ap.add_argument("--data", default="out")
ap.add_argument("--out", default="dataset/flows.csv")
a = ap.parse_args()

parts = []
for d in sorted(glob.glob(f"{a.data}/S*")):
    lp, pp = f"{d}/labels.json", f"{d}/capture.pcap"
    if not (os.path.exists(lp) and os.path.exists(pp)):
        print(f"skip {d} (not finished)")
        continue
    lab = json.load(open(lp))
    rows = []
    table = FlowTable(rows.append)
    with open(pp, "rb") as fh:
        for ts, buf in dpkt.pcap.Reader(fh):
            table.add(ts, buf)
    table.flush()

    df = pd.DataFrame(rows, columns=META + FEATURES)
    att = {x["ip"]: x["cls"] for x in lab["attackers"]}
    known = set(lab["servers"]) | set(lab["clients"]) | set(att)
    df = df[df.src_ip.isin(known) & df.dst_ip.isin(known)].copy()
    df["label"] = df.src_ip.map(att).fillna(df.dst_ip.map(att)).fillna("benign")
    df["session_id"] = lab["session_id"]
    df["topology"] = lab["params"]["topology"]
    df["split_group"] = lab["params"]["split_group"]
    parts.append(df)
    print(f"{lab['session_id']}: {len(df)} flows  {df.label.value_counts().to_dict()}")

os.makedirs(os.path.dirname(a.out), exist_ok=True)
out = pd.concat(parts, ignore_index=True)
out.to_csv(a.out, index=False)
print(f"\nSaved {len(out)} flows -> {a.out}")
print(out.groupby(["label", "split_group"]).size().unstack(fill_value=0))
