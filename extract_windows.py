#!/usr/bin/env python3
"""Turn every out/<session>/capture.pcap into time-window features, one row per
(window, server). Output: dataset/windows_<W>s.csv

Label rule (per row):
  attack packets = packets whose source or destination MAC belongs to an attacker host.
                   Each attacker host runs only one attack type, so its MAC gives the class.
  >= --min-attack-pkts  -> that attacker's class
  1 .. min-1            -> dropped as ambiguous (counted in the summary)
  0                     -> benign

Columns in META are for splitting and auditing only. Drop them before training.
"""
import argparse
import glob
import json
import math
import os
import socket
from collections import Counter, defaultdict

import dpkt
import numpy as np
import pandas as pd

META = ["session_id", "window_start", "server_ip", "topology", "split_group",
        "attack_pkts", "attack_frac", "label"]

FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20


def mac_str(b):
    return ":".join(f"{x:02x}" for x in b)


def entropy(c):
    n = sum(c.values())
    if n == 0:
        return 0.0
    return -sum(v / n * math.log2(v / n) for v in c.values())


def new_acc():
    return {"lens": [], "ts": [], "src": Counter(), "dport": Counter(),
            "src_dports": defaultdict(set), "tcp": 0, "udp": 0, "icmp": 0,
            "syn_only": 0, "ack": 0, "fin_noack": 0, "rst_in": 0, "psh": 0,
            "null": 0, "xmas": 0, "get": 0, "out_pkts": 0, "out_bytes": 0,
            "out_rst": 0, "out_synack": 0, "out_unreach": 0, "att": Counter()}


def features(a, W):
    n = len(a["lens"])
    lens = np.array(a["lens"], dtype=float)
    ts = np.sort(np.array(a["ts"]))
    iat = np.diff(ts) if n > 1 else np.array([0.0])
    src_counts = a["src"]
    return {
        "in_pkts": n,
        "in_bytes": float(lens.sum()),
        "in_pps": n / W,
        "in_bps": lens.sum() * 8 / W,
        "len_mean": lens.mean(),
        "len_std": lens.std(),
        "len_min": lens.min(),
        "len_max": lens.max(),
        "iat_mean": float(iat.mean()),
        "iat_std": float(iat.std()),
        "tcp_frac": a["tcp"] / n,
        "udp_frac": a["udp"] / n,
        "icmp_frac": a["icmp"] / n,
        "syn_only": a["syn_only"],
        "syn_frac": a["syn_only"] / n,
        "ack_frac": a["ack"] / n,
        "fin_noack": a["fin_noack"],
        "rst_in": a["rst_in"],
        "psh_frac": a["psh"] / n,
        "null_flags": a["null"],
        "xmas_flags": a["xmas"],
        "uniq_src": len(src_counts),
        "src_entropy": entropy(src_counts),
        "top_src_share": max(src_counts.values()) / n,
        "single_pkt_src_frac": sum(1 for v in src_counts.values() if v == 1) / len(src_counts),
        "uniq_dport": len(a["dport"]),
        "dport_entropy": entropy(a["dport"]),
        "max_dports_per_src": max((len(s) for s in a["src_dports"].values()), default=0),
        "uniq_src_dport": sum(len(s) for s in a["src_dports"].values()),
        "http_get": a["get"],
        "out_pkts": a["out_pkts"],
        "out_bytes": a["out_bytes"],
        "out_rst": a["out_rst"],
        "out_synack": a["out_synack"],
        "out_icmp_unreach": a["out_unreach"],
        "out_in_ratio": a["out_pkts"] / n,
        "synack_syn_ratio": a["out_synack"] / max(a["syn_only"], 1),
    }


def process(session_dir, W, min_att):
    lab = json.load(open(f"{session_dir}/labels.json"))
    servers = set(lab["servers"])
    att_macs = {x["mac"]: x["cls"] for x in lab["attackers"]}
    t0 = lab["capture_start"]
    accs = defaultdict(new_acc)
    rows, ambiguous = [], 0

    def flush(keys):
        nonlocal ambiguous
        for k in keys:
            a = accs.pop(k)
            if not a["lens"]:  # only outbound packets in this window
                continue
            n_att = sum(a["att"].values())
            if 0 < n_att < min_att:
                ambiguous += 1
                continue
            f = features(a, W)
            f.update({"session_id": lab["session_id"], "window_start": k[0] * W,
                      "server_ip": k[1], "topology": lab["params"]["topology"],
                      "split_group": lab["params"]["split_group"], "attack_pkts": n_att,
                      "attack_frac": n_att / (len(a["lens"]) + a["out_pkts"]),
                      "label": a["att"].most_common(1)[0][0] if n_att >= min_att else "benign"})
            rows.append(f)

    cur_w = 0
    with open(f"{session_dir}/capture.pcap", "rb") as fh:
        for ts, buf in dpkt.pcap.Reader(fh):
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                if not isinstance(ip, dpkt.ip.IP):
                    continue
                src, dst = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)
            except Exception:
                continue
            if dst in servers:
                inbound, srv = True, dst
            elif src in servers:
                inbound, srv = False, src
            else:
                continue
            w = int((ts - t0) // W)
            if w < 0:
                continue
            if w > cur_w:  # pcap is in time order: finish older windows
                flush([k for k in accs if k[0] < w])
                cur_w = w
            a = accs[(w, srv)]
            m = att_macs.get(mac_str(eth.src)) or att_macs.get(mac_str(eth.dst))
            if m:
                a["att"][m] += 1
            l4 = ip.data
            if not inbound:
                a["out_pkts"] += 1
                a["out_bytes"] += ip.len
                if isinstance(l4, dpkt.tcp.TCP):
                    if l4.flags & RST:
                        a["out_rst"] += 1
                    if l4.flags & SYN and l4.flags & ACK:
                        a["out_synack"] += 1
                elif isinstance(l4, dpkt.icmp.ICMP) and l4.type == 3:
                    a["out_unreach"] += 1
                continue

            a["lens"].append(ip.len)
            a["ts"].append(ts)
            a["src"][src] += 1
            if isinstance(l4, dpkt.tcp.TCP):
                fl = l4.flags
                a["tcp"] += 1
                a["dport"][l4.dport] += 1
                a["src_dports"][src].add(("t", l4.dport))
                if fl & SYN and not fl & ACK:
                    a["syn_only"] += 1
                if fl & ACK:
                    a["ack"] += 1
                if fl & FIN and not fl & ACK:
                    a["fin_noack"] += 1
                if fl & RST:
                    a["rst_in"] += 1
                if fl & PSH:
                    a["psh"] += 1
                if fl == 0:
                    a["null"] += 1
                if fl & (FIN | PSH | URG) == (FIN | PSH | URG) and not fl & ACK:
                    a["xmas"] += 1
                if bytes(l4.data[:4]) == b"GET ":
                    a["get"] += 1
            elif isinstance(l4, dpkt.udp.UDP):
                a["udp"] += 1
                a["dport"][l4.dport] += 1
                a["src_dports"][src].add(("u", l4.dport))
            elif isinstance(l4, dpkt.icmp.ICMP):
                a["icmp"] += 1
    flush(list(accs))
    return rows, ambiguous


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="out")
    ap.add_argument("--out", default="dataset")
    ap.add_argument("--window", type=float, default=2.0, help="window size in seconds")
    ap.add_argument("--min-attack-pkts", type=int, default=5)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    all_rows, summary = [], []
    for d in sorted(glob.glob(f"{a.data}/S*")):
        if not os.path.exists(f"{d}/labels.json"):
            print(f"skip {d} (not finished)")
            continue
        rows, amb = process(d, a.window, a.min_attack_pkts)
        all_rows += rows
        summary.append({"session": os.path.basename(d), "rows": len(rows), "ambiguous": amb})
        print(f"{os.path.basename(d)}: {len(rows)} rows, {amb} ambiguous dropped")

    df = pd.DataFrame(all_rows)
    feat_cols = [c for c in df.columns if c not in META]
    df = df[META[:-1] + feat_cols + ["label"]]
    path = f"{a.out}/windows_{a.window:g}s.csv"
    df.to_csv(path, index=False)
    pd.DataFrame(summary).to_csv(f"{a.out}/extract_summary.csv", index=False)
    print(f"\nSaved {len(df)} rows, {len(feat_cols)} features -> {path}")
    print(df.groupby(["label", "split_group"]).size().unstack(fill_value=0))


if __name__ == "__main__":
    main()
