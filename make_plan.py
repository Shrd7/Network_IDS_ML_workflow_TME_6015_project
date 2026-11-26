#!/usr/bin/env python3
"""Create plan.csv: one row per capture run.

Mode 'mixed' (default, fastest): every run contains all 4 attacks in turn, with benign
traffic all the time. The last run uses the 'tree' topology and is held out for testing.
    python3 make_plan.py                                  # small: 4 runs x 10 min, ~0.5-1 GB
    python3 make_plan.py --size full --duration 1200      # full: 4 runs x 20 min, ~4-12 GB

--size small: small web pages, slower links (10/20 Mbps), fewer users, rate-limited
              attacks, shorter episodes. Same classes and same steps, much less data.

Mode 'per-class': each run has one class only (benign runs have no attacks).
    python3 make_plan.py --mode per-class --per-class 6 --duration 180   # ~1.75 h
"""
import argparse
import csv
import random

CLASSES = ["benign", "http_flood", "slow_dos", "port_scan", "ssh_brute"]

p = argparse.ArgumentParser()
p.add_argument("--mode", choices=["mixed", "per-class"], default="mixed")
p.add_argument("--runs", type=int, default=4, help="mixed mode: number of runs")
p.add_argument("--per-class", type=int, default=6, help="per-class mode: runs per class")
p.add_argument("--duration", type=int, default=600, help="seconds per run")
p.add_argument("--size", choices=["small", "full"], default="small")
p.add_argument("--seed", type=int, default=42)
p.add_argument("--out", default="plan.csv")
a = p.parse_args()
rng = random.Random(a.seed)


def conditions(topology, held):
    return {"topology": topology, "split_group": "heldout" if held else "main",
            "size": a.size,
            "bw_mbps": rng.choice([10, 20] if a.size == "small" else [10, 50, 100]),
            "delay": rng.choice(["1ms", "5ms", "20ms"]),
            "loss_pct": rng.choice([0, 0, 0.5, 1]),
            "n_clients": rng.choice([3, 4, 5] if a.size == "small" else [4, 6, 8]),
            "think_s": rng.choice([0.5, 1.0, 2.0]), "duration": a.duration,
            "seed": rng.randrange(10**6)}


rows = []
if a.mode == "mixed":
    for i in range(a.runs):
        held = i == a.runs - 1
        topo = "tree" if held else ("star" if i % 2 == 0 else "linear")
        rows.append({"cls": "mixed", **conditions(topo, held)})
else:
    for cls in CLASSES:
        n_held = max(1, a.per_class // 4)
        for i in range(a.per_class):
            held = i < n_held
            topo = "tree" if held else ("star" if i % 2 == 0 else "linear")
            rows.append({"cls": cls, **conditions(topo, held)})
    rng.shuffle(rows)

for k, r in enumerate(rows, 1):
    r["session_id"] = f"S{k:03d}"
cols = ["session_id"] + [c for c in rows[0] if c != "session_id"]
with open(a.out, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=cols)
    w.writeheader()
    w.writerows(rows)
total_min = sum(int(r["duration"]) + 20 for r in rows) / 60
print(f"Wrote {len(rows)} runs to {a.out} (about {total_min:.0f} min to capture)")
