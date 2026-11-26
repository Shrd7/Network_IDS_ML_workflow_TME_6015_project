#!/usr/bin/env python3
"""Downstream application: live attack detection and blocking in Mininet.

Runs one demo session (benign users + all 4 attacks, same as a dataset run) and,
in 'detect' mode, a live detector:

  tcpdump on the server uplink (s99-eth1)
    -> flowfeat.FlowTable (same CIC-style features as training)
    -> trained model (models/detector.npz, exported by the notebook; NumPy only)
    -> per source IP: >= MIN_FLOWS attack flows and >= MIN_FRAC of its flows in the
       last WINDOW seconds  ->  OpenFlow drop rule for that IP on every switch
       (expires after BLOCK_SECS), and the attacker's already-open connections on the
       servers are closed (ss -K), so held slots (e.g. slow DoS) are freed at once

A probe on h1 requests a page from both web servers every 0.5 s, to measure what
users experience. h1 is a monitoring host: it runs only the probe and is on the
detector's allow-list (like monitoring systems in real networks). The other 4
clients are normal users and are NOT allow-listed, so false blocks are still tested. Run the same seed twice to compare:

  sudo python3 live_detector.py --mode baseline     # no protection
  sudo python3 live_detector.py --mode detect       # with the detector

Live dashboard: open http://localhost:8080 in Firefox on Kali while it runs.
It refreshes every second (dashboard.html reads live.json). After the run the page
stays up with the final result until you press Ctrl+C (use --no-hold to exit at once).

Output in results/demo_<mode>/: probe.csv, alerts.csv, summary.json, live.json
The detect run also prints a side-by-side comparison if the baseline run exists.
"""
import argparse
import collections
import functools
import http.server
import json
import shutil
import os
import random
import subprocess
import sys
import threading
import time

import dpkt
try:
    import joblib
except ImportError:
    joblib = None
import numpy as np
import pandas as pd

import run_session as rs
from flowfeat import FlowTable, transform

PROBE = r'''
import sys, time, urllib.request
out = open(sys.argv[1], "w", buffering=1)
end = time.time() + float(sys.argv[2])
while time.time() < end:
    for s in ("10.0.0.101", "10.0.0.102"):
        t = time.time(); ok = 0
        try:
            urllib.request.urlopen(f"http://{s}/p001.html", timeout=2).read(); ok = 1
        except Exception:
            pass
        out.write(f"{t:.3f},{s},{ok},{time.time() - t:.4f}\n")
    time.sleep(0.5)
'''


class NumpyMLP:
    """Forward pass of the exported MLP (ReLU between layers). Needs NumPy only."""

    def __init__(self, z):
        n = int(z["n_layers"])
        self.W = [z[f"W{i}"] for i in range(n)]
        self.b = [z[f"b{i}"] for i in range(n)]
        self.classes = np.array([str(c) for c in z["classes"]])

    def predict(self, X):
        h = X
        for i, (W, b) in enumerate(zip(self.W, self.b)):
            h = h @ W + b
            if i < len(self.W) - 1:
                h = np.maximum(h, 0)
        return self.classes[h.argmax(1)]


class NumpyScaler:
    def __init__(self, mean, scale):
        self.mean, self.scale = mean, scale

    def transform(self, X):
        return (X - self.mean) / self.scale


def load_model(path):
    if path.endswith(".npz"):
        z = np.load(path, allow_pickle=False)
        return {"name": str(z["name"]), "model": NumpyMLP(z),
                "scaler": NumpyScaler(z["mean"], z["scale"]),
                "features": [str(f) for f in z["features"]],
                "classes": [str(c) for c in z["classes"]]}
    return joblib.load(path)  # older scikit-learn bundle


class Detector:
    def __init__(self, bundle, iface, switches, args, t0, log, server_pids=()):
        self.b, self.iface, self.switches, self.args, self.t0 = bundle, iface, switches, args, t0
        self.server_pids = list(server_pids)
        self.log = log
        self.servers = set(ip for ip, _ in rs.SERVERS.values())
        self.allow = set(args.allow.split(",")) if args.allow else set()
        self.lock = threading.Lock()
        self.queue = []                       # finished flows waiting for prediction
        self.table = FlowTable(self.queue.append)
        self.seen_snap = set()                # open flows already checked once
        self.hist = collections.defaultdict(collections.deque)  # src -> (time, pred)
        self.blocked = {}                     # src -> blocked until
        self.alerts = []
        self.flows_total = 0
        self.pred_counts = collections.Counter()
        self.stop = threading.Event()
        m = self.b["model"]
        if hasattr(m, "n_jobs"):
            m.n_jobs = 1

    def start(self):
        self.proc = subprocess.Popen(["tcpdump", "-i", self.iface, "-U", "-w", "-", "-s", "0", "-q"],
                                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        threading.Thread(target=self._read, daemon=True).start()
        threading.Thread(target=self._decide, daemon=True).start()

    def close(self):
        self.stop.set()
        self.proc.terminate()

    def _read(self):
        try:
            for ts, buf in dpkt.pcap.Reader(self.proc.stdout):
                with self.lock:
                    self.table.add(ts, buf)
        except Exception:
            pass

    def _predict(self, flows):
        df = pd.DataFrame(flows)
        X = self.b["scaler"].transform(transform(df[self.b["features"]].values))
        return df, self.b["model"].predict(X)

    def _block(self, ip, cls, n, frac, now):
        until = now + self.args.block_secs
        self.blocked[ip] = until
        for sw in self.switches:
            subprocess.run(["ovs-ofctl", "add-flow", sw,
                            f"priority=100,ip,nw_src={ip},hard_timeout={self.args.block_secs},actions=drop"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for pid in self.server_pids:  # close the attacker's open connections on each server
            subprocess.run(["nsenter", "-t", str(pid), "-n", "ss", "-K", "dst", ip],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        rel = now - self.t0
        self.alerts.append({"t": round(rel, 1), "src_ip": ip, "pred": cls, "flows": n,
                            "attack_frac": round(frac, 2)})
        msg = f"  [{rel:6.1f}s] ALERT {cls} from {ip} ({n} flows, {frac:.0%}) -> BLOCKED {self.args.block_secs}s, open connections closed"
        print(msg)
        self.log.write(msg + "\n")
        self.log.flush()

    def _decide(self):
        a = self.args
        last_snap = 0
        while not self.stop.is_set():
            time.sleep(1)
            now = time.time()
            with self.lock:
                self.table.expire(now, a.live_idle)      # end idle flows quickly
                flows, self.queue[:] = list(self.queue), []
                if now - last_snap >= 5:                 # long open flows (e.g. slow DoS)
                    last_snap = now
                    for k, f in self.table.flows.items():
                        if now - f.start >= a.snapshot_age and k not in self.seen_snap:
                            self.seen_snap.add(k)
                            flows.append(f.features())
            if not flows:
                continue
            df, pred = self._predict(flows)
            self.flows_total += len(pred)
            self.pred_counts.update(pred)
            for src, dst, p in zip(df.src_ip, df.dst_ip, pred):
                client = dst if src in self.servers else src
                if client in self.servers or client in self.allow:
                    continue
                self.hist[client].append((now, p))
            for ip, dq in self.hist.items():
                while dq and dq[0][0] < now - a.window:
                    dq.popleft()
                if self.blocked.get(ip, 0) > now or not dq:
                    continue
                att = [p for _, p in dq if p != "benign"]
                frac = len(att) / len(dq)
                if len(att) >= a.min_flows and frac >= a.min_frac:
                    cls = collections.Counter(att).most_common(1)[0][0]
                    self._block(ip, cls, len(att), frac, now)


def read_probe(path, t0):
    try:
        p = pd.read_csv(path, names=["t", "server", "ok", "latency"])
    except Exception:
        return pd.DataFrame(columns=["t", "server", "ok", "latency"])
    p["t"] -= t0
    return p[p.t >= 0]


def write_state(outdir, a, t0, det, episodes, current, done=False, summary=None, baseline=None):
    now = min(time.time() - t0, a.duration)
    p = read_probe(f"{outdir}/probe.csv", t0)
    last = p[p.t >= now - 30]
    buckets = []
    if len(p):
        p["b"] = (p.t // 5 * 5).astype(int)
        buckets = [[int(b), float(g.ok.mean())] for b, g in p.groupby("b")]
    eps = [{"cls": e["cls"], "intensity": e["intensity"], "attacker": e["attacker"],
            "target": e["target"], "start": e["start"] - t0,
            "end": (e["end"] - t0) if "end" in e else None} for e in episodes + ([current] if current else [])]
    blocked = []
    if det:
        for ip, until in det.blocked.items():
            if until > time.time():
                cls = next((x["pred"] for x in reversed(det.alerts) if x["src_ip"] == ip), "")
                blocked.append({"ip": ip, "cls": cls, "left": until - time.time()})
    classes = ["benign", "http_flood", "port_scan", "slow_dos", "ssh_brute"]
    st = {
        "mode": a.mode, "model": det.b["name"] if det else None, "t": min(now, a.duration),
        "duration": a.duration, "done": done,
        "attack": None if not current else {**{k: current[k] for k in ("cls", "intensity", "attacker", "target")},
                                            "start": current["start"] - t0},
        "episodes": eps,
        "flows_total": det.flows_total if det else 0,
        "pred_counts": {c: int(det.pred_counts.get(c, 0)) if det else 0 for c in classes},
        "alerts": det.alerts if det else [],
        "blocked": blocked,
        "probe": {"success_30s": float(last.ok.mean()) if len(last) else None,
                  "latency_ms_30s": float(last[last.ok == 1].latency.median() * 1000) if (last.ok == 1).any() else None,
                  "buckets": buckets},
        "summary": summary, "baseline": baseline,
    }
    tmp = f"{outdir}/live.json.tmp"
    with open(tmp, "w") as f:
        json.dump(st, f, default=float)
    os.replace(tmp, f"{outdir}/live.json")


def start_dashboard(outdir, port):
    shutil.copy(os.path.join(rs.HERE, "dashboard.html"), f"{outdir}/index.html")

    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass

    srv = http.server.ThreadingHTTPServer(("0.0.0.0", port), functools.partial(Quiet, directory=outdir))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def summarize(outdir, episodes, alerts, t0, mode):
    probe = pd.read_csv(f"{outdir}/probe.csv", names=["t", "server", "ok", "latency"])
    probe["t"] -= t0
    probe["under_attack"] = False
    for ep in episodes:
        m = (probe.t >= ep["start"] - t0) & (probe.t <= ep["end"] - t0) & (probe.server == ep["target"])
        probe.loc[m, "under_attack"] = True
    att = {v[1]: c for c, v in rs.ATTACKERS.items()}
    ep_rows = []
    for ep in episodes:
        s, e = ep["start"] - t0, ep["end"] - t0
        hits = [x for x in alerts if x["src_ip"] == ep["attacker"] and s - 1 <= x["t"] <= e + 30]
        earlier = [x for x in alerts if x["src_ip"] == ep["attacker"] and x["t"] < s - 1]
        ep_rows.append({"cls": ep["cls"], "intensity": ep["intensity"], "start_s": round(s, 1),
                        "detected": bool(hits), "delay_s": round(hits[0]["t"] - s, 1) if hits else None,
                        "pred": hits[0]["pred"] if hits else None,
                        "blocked_earlier": bool(earlier)})
    ua, na = probe[probe.under_attack], probe[~probe.under_attack]
    summ = {
        "mode": mode,
        "probe_success_under_attack": round(ua.ok.mean(), 4) if len(ua) else None,
        "probe_success_no_attack": round(na.ok.mean(), 4) if len(na) else None,
        "probe_median_latency_under_attack_ms": round(ua[ua.ok == 1].latency.median() * 1000, 1) if (ua.ok == 1).any() else None,
        "episodes": ep_rows,
        "episodes_detected": sum(r["detected"] for r in ep_rows),
        "episodes_total": len(ep_rows),
        "correct_class": sum(1 for r in ep_rows if r["detected"] and r["pred"] == r["cls"]),
        "median_delay_s": float(np.median([r["delay_s"] for r in ep_rows if r["delay_s"] is not None]))
        if any(r["delay_s"] is not None for r in ep_rows) else None,
        "false_blocks": [x for x in alerts if x["src_ip"] not in att],
    }
    json.dump(summ, open(f"{outdir}/summary.json", "w"), indent=2)
    return summ


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["detect", "baseline"], required=True)
    ap.add_argument("--duration", type=float, default=300)
    ap.add_argument("--seed", type=int, default=7, help="same seed = same attack schedule")
    ap.add_argument("--model", default="models/detector.npz")
    ap.add_argument("--window", type=float, default=10, help="seconds of history per source IP")
    ap.add_argument("--min-flows", type=int, default=5)
    ap.add_argument("--min-frac", type=float, default=0.6)
    ap.add_argument("--block-secs", type=int, default=120)
    ap.add_argument("--live-idle", type=float, default=10, help="end a flow after N s idle (live)")
    ap.add_argument("--snapshot-age", type=float, default=15, help="check open flows older than N s")
    ap.add_argument("--nginx-conns", type=int, default=128, help="web server connection slots per worker")
    ap.add_argument("--allow", default="10.0.0.1", help="comma separated IPs never blocked (monitor host)")
    ap.add_argument("--port", type=int, default=8080, help="dashboard web port")
    ap.add_argument("--no-hold", action="store_true", help="exit at the end instead of keeping the dashboard up")
    a = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("Run with sudo.")

    from mininet.log import setLogLevel
    setLogLevel("warning")
    subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    rs.NGINX_CONNS = a.nginx_conns
    outdir = f"results/demo_{a.mode}"
    os.makedirs(outdir, exist_ok=True)
    bundle = load_model(a.model) if a.mode == "detect" else None
    if bundle:
        print(f"Model: {bundle['name']}")

    row = {"session_id": f"DEMO_{a.mode}", "cls": "mixed", "topology": "star", "split_group": "demo",
           "size": "small", "bw_mbps": 10, "delay": "5ms", "loss_pct": 0, "n_clients": 5,
           "think_s": 1.0, "duration": a.duration, "seed": a.seed}
    rng = random.Random(a.seed)
    rs.make_files("small")
    net, clients, attackers, iface = rs.build_net(row)
    switches = [s.name for s in net.switches]
    procs, det, episodes = [], None, []
    log = open(f"{outdir}/alerts.log", "w")
    for f in ("probe.csv", "live.json"):
        if os.path.exists(f"{outdir}/{f}"):
            os.remove(f"{outdir}/{f}")
    srv = start_dashboard(outdir, a.port)
    cur = {"ep": None}
    stop_writer = threading.Event()
    try:
        rs.start_servers(net, "small")
        t0 = time.time()
        server_ips = ",".join(ip for ip, _ in rs.SERVERS.values())
        for i, h in enumerate(clients, 1):
            if i == 1:
                continue  # h1 = monitoring host: probe only, no user traffic
            procs.append(h.popen(
                ["python3", f"{rs.HERE}/benign.py", "--servers", server_ips, "--ssh", rs.SSH_SERVER,
                 "--port", str(5200 + i), "--seed", str(a.seed * 100 + i), "--duration",
                 str(a.duration + 30), "--think", "1.0", "--small"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        procs.append(clients[0].popen(["python3", "-c", PROBE, os.path.abspath(f"{outdir}/probe.csv"),
                                       str(a.duration)], stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL))
        if bundle:
            det = Detector(bundle, iface, switches, a, t0, log,
                           server_pids=[net.get(n).pid for n in rs.SERVERS])
            det.start()

        def writer():
            while not stop_writer.is_set():
                try:
                    write_state(outdir, a, t0, det, episodes, cur["ep"])
                except Exception:
                    pass
                time.sleep(1)
        threading.Thread(target=writer, daemon=True).start()
        print(f"Dashboard: http://localhost:{a.port}  (open it in Firefox now)")
        print(f"Demo ({a.mode}) running for {a.duration:.0f}s ...")

        for (s, e, cls) in rs.schedule(rng, a.duration, "mixed", "small"):
            time.sleep(max(0, t0 + s - time.time()))
            intensity = rng.choice(["low", "med", "high"])
            target, cmd = rs.attack_cmd(cls, rng, intensity, e - s, "small")
            h = attackers[cls]
            ep = {"cls": cls, "start": time.time(), "intensity": intensity, "target": target,
                  "attacker": h.IP()}
            p = h.popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            cur["ep"] = ep
            print(f"  [{ep['start'] - t0:6.1f}s] attack starts: {cls} ({intensity}) from {h.IP()} -> {target}")
            time.sleep(max(0, t0 + e - time.time()))
            p.terminate()
            h.cmd("pkill -f http_flood.py; pkill -f slowhttptest; pkill -f nmap; pkill -f hydra")
            ep["end"] = time.time()
            episodes.append(ep)
            cur["ep"] = None
        time.sleep(max(0, t0 + a.duration - time.time()))
    finally:
        stop_writer.set()
        if det:
            det.close()
        for p in procs:
            p.terminate()
        time.sleep(2)
        rs.stop_servers()
        net.stop()
        log.close()

    alerts = det.alerts if det else []
    pd.DataFrame(alerts, columns=["t", "src_ip", "pred", "flows", "attack_frac"]).to_csv(
        f"{outdir}/alerts.csv", index=False)
    summ = summarize(outdir, episodes, alerts, t0, a.mode)

    print("\n=== Episodes")
    print(pd.DataFrame(summ["episodes"]).to_string(index=False))
    print(f"\nDetected {summ['episodes_detected']}/{summ['episodes_total']} episodes, "
          f"correct class {summ['correct_class']}, median delay {summ['median_delay_s']} s, "
          f"false blocks {len(summ['false_blocks'])}")
    other = "results/demo_baseline/summary.json"
    if a.mode == "detect" and os.path.exists(other):
        b = json.load(open(other))
        keys = ["probe_success_under_attack", "probe_success_no_attack",
                "probe_median_latency_under_attack_ms"]
        print("\n=== Baseline vs detect (what users experience)")
        print(pd.DataFrame({"baseline": [b[k] for k in keys], "detect": [summ[k] for k in keys]},
                           index=keys).to_string())
    baseline = json.load(open(other)) if (a.mode == "detect" and os.path.exists(other)) else None
    write_state(outdir, a, t0, det, episodes, None, done=True, summary=summ, baseline=baseline)
    print(f"\nSaved to {outdir}/")
    if not a.no_hold:
        print(f"Dashboard still up at http://localhost:{a.port} - press Ctrl+C to exit.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    srv.shutdown()


if __name__ == "__main__":
    main()
