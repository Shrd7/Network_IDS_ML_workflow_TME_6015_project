#!/usr/bin/env python3
"""Run capture runs in Mininet. Must run with sudo.

  sudo python3 run_session.py --session S001 --duration 120   # quick test
  sudo python3 run_session.py --all                           # all runs (skips finished ones)

Network:
  clients h1..hN, attackers a1..a4  ->  access switch(es)  ->  core s1
  s1 --(uplink)-- s99 -- srv1 10.0.0.101 (web, DNS, SSH, iperf3)
                      -- srv2 10.0.0.102 (web, iperf3)
tcpdump records the uplink s99-eth1: all client/attacker <-> server traffic crosses it once.

Each attack type has its own attacker host, so labels come from the attacker IP/MAC:
  a1 10.0.0.201  http_flood  (like CIC-IDS2017 'DoS Hulk')
  a2 10.0.0.202  slow_dos    (like 'DoS slowloris' / 'DoS Slowhttptest')
  a3 10.0.0.203  port_scan   (like 'PortScan')
  a4 10.0.0.204  ssh_brute   (like 'SSH-Patator')

Output in out/<session_id>/: capture.pcap, labels.json
"""
import argparse
import csv
import json
import os
import random
import shlex
import subprocess
import sys
import time
from functools import partial

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = "/tmp/ds"
WORDS = f"{WORK}/words.txt"

SERVERS = {"srv1": ("10.0.0.101", "00:00:00:00:01:01"),
           "srv2": ("10.0.0.102", "00:00:00:00:01:02")}
SSH_SERVER = "10.0.0.101"
ATTACKERS = {"http_flood": ("a1", "10.0.0.201", "00:00:00:00:aa:01"),
             "slow_dos":   ("a2", "10.0.0.202", "00:00:00:00:aa:02"),
             "port_scan":  ("a3", "10.0.0.203", "00:00:00:00:aa:03"),
             "ssh_brute":  ("a4", "10.0.0.204", "00:00:00:00:aa:04")}
ATTACK_CLASSES = list(ATTACKERS)
IPERF_PORTS = range(5201, 5211)
NGINX_CONNS = 4096  # live_detector.py lowers this for the demo

NMAP_TIMING = {"low": "-T3", "med": "-T4", "high": "-T5"}

# 'small' = same attacks and steps, but less data: small pages, rate-limited floods,
# fewer scanned ports, shorter episodes.
PROFILES = {
    "full": {
        "page_kb": (1, 200), "big_mb": (2, 20),
        "http_threads": {"low": 5, "med": 20, "high": 60},
        "http_delay": {"low": 0, "med": 0, "high": 0},
        "slow_conns": {"low": 200, "med": 500, "high": 1000},
        "scan_ports": ["--top-ports 1000", "-p 1-10000", "-p-"], "scan_pause": 1,
        "hydra_tasks": {"low": 4, "med": 8, "high": 16},
        "ep_len": (40, 70), "gap": (30, 50),
    },
    "small": {
        "page_kb": (0.5, 10), "big_mb": (1, 2),
        "http_threads": {"low": 3, "med": 8, "high": 15},
        "http_delay": {"low": 0.1, "med": 0.05, "high": 0.02},
        "slow_conns": {"low": 100, "med": 200, "high": 400},
        "scan_ports": ["--top-ports 100", "--top-ports 500", "--top-ports 1000"], "scan_pause": 5,
        "hydra_tasks": {"low": 4, "med": 8, "high": 16},
        "ep_len": (25, 40), "gap": (20, 30),
    },
}


def www_dir(size):
    return f"{WORK}/www_{size}"


# ---------------------------------------------------------------- files
def make_files(size):
    P, www = PROFILES[size], www_dir(size)
    os.makedirs(www, exist_ok=True)
    if not os.path.exists(f"{www}/big5.bin"):
        rng = random.Random(7)
        lo, hi = (int(x * 1000) for x in P["page_kb"])
        for i in range(200):
            with open(f"{www}/p{i:03d}.html", "w") as f:
                f.write("<html><body>" + "x" * rng.randint(lo, hi) + "</body></html>")
        for i in range(1, 6):
            with open(f"{www}/big{i}.bin", "wb") as f:
                f.write(os.urandom(int(rng.uniform(*P["big_mb"]) * 1_000_000)))
    if not os.path.exists(WORDS):
        r = random.Random(1)
        base = ["password", "123456", "admin", "welcome", "qwerty", "letmein", "dragon",
                "monkey", "football", "shadow", "master", "sunshine", "login", "root", "ubuntu"]
        words = set(base)
        while len(words) < 2000:
            words.add(r.choice(base) + str(r.randint(0, 9999)) + r.choice(["", "!", "@", "#"]))
        with open(WORDS, "w") as f:
            f.write("\n".join(sorted(words)) + "\n")
    os.system(f"chmod -R a+rX {WORK}")
    os.makedirs("/run/sshd", exist_ok=True)


def nginx_conf(name, www):
    d = f"{WORK}/{name}"
    os.makedirs(d, exist_ok=True)
    with open(f"{d}/nginx.conf", "w") as f:
        f.write(f"""user www-data;
worker_processes 2;
pid {d}/nginx.pid;
error_log {d}/error.log warn;
events {{ worker_connections {NGINX_CONNS}; }}
http {{
  access_log off;
  sendfile on;
  keepalive_timeout 15;
  keepalive_requests 100;
  server {{ listen 80; root {www}; }}
}}
""")
    return f"{d}/nginx.conf"


def sshd_conf():
    d = f"{WORK}/srv1"
    with open(f"{d}/sshd_config", "w") as f:
        f.write(f"""ListenAddress {SSH_SERVER}
PidFile {d}/sshd.pid
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
PasswordAuthentication yes
KbdInteractiveAuthentication no
UsePAM yes
MaxStartups 200:30:400
MaxAuthTries 2
UseDNS no
AllowUsers labuser
""")
    return f"{d}/sshd_config"


# ---------------------------------------------------------------- topology
def build_net(row):
    from mininet.net import Mininet
    from mininet.node import OVSSwitch
    from mininet.link import TCLink

    sw = partial(OVSSwitch, failMode="standalone")  # normal learning switch, no controller
    net = Mininet(controller=None, switch=sw, link=TCLink, build=False)
    lp = dict(bw=float(row["bw_mbps"]), delay=row["delay"], loss=float(row["loss_pct"]))

    s99 = net.addSwitch("s99")
    s1 = net.addSwitch("s1")
    uplink = net.addLink(s99, s1)  # added first, so it is s99-eth1 (no speed limit)

    topo = row["topology"]
    if topo == "star":
        access = [s1]
    elif topo == "linear":
        s2, s3 = net.addSwitch("s2"), net.addSwitch("s3")
        net.addLink(s1, s2, **lp)
        net.addLink(s2, s3, **lp)
        access = [s1, s2, s3]
    elif topo == "tree":
        s2, s3 = net.addSwitch("s2"), net.addSwitch("s3")
        net.addLink(s1, s2, **lp)
        net.addLink(s1, s3, **lp)
        access = []
        for parent, kids in ((s2, ("s4", "s5")), (s3, ("s6", "s7"))):
            for k in kids:
                s = net.addSwitch(k)
                net.addLink(parent, s, **lp)
                access.append(s)
    else:
        raise ValueError(topo)

    for name, (ip, mac) in SERVERS.items():
        net.addLink(net.addHost(name, ip=f"{ip}/24", mac=mac), s99)

    clients = []
    for i in range(1, int(row["n_clients"]) + 1):
        h = net.addHost(f"h{i}", ip=f"10.0.0.{i}/24", mac=f"00:00:00:00:00:{i:02x}")
        net.addLink(h, access[(i - 1) % len(access)], **lp)
        clients.append(h)

    attackers = {}
    for k, (cls, (name, ip, mac)) in enumerate(ATTACKERS.items()):
        h = net.addHost(name, ip=f"{ip}/24", mac=mac)
        net.addLink(h, access[-1 - (k % len(access))], **lp)
        attackers[cls] = h

    net.build()
    net.start()
    return net, clients, attackers, uplink.intf1.name


# ---------------------------------------------------------------- servers
def start_servers(net, size):
    for name in SERVERS:
        h = net.get(name)
        h.cmd(f"nginx -c {nginx_conf(name, www_dir(size))}")
        for port in IPERF_PORTS:
            h.cmd(f"iperf3 -s -D -p {port} -I {WORK}/{name}/iperf{port}.pid")
    srv1 = net.get("srv1")
    srv1.cmd(f"dnsmasq --no-resolv --no-hosts --bind-interfaces --listen-address={SSH_SERVER} "
             f"--address=/lab/{SERVERS['srv2'][0]} --pid-file={WORK}/srv1/dnsmasq.pid")
    srv1.cmd(f"/usr/sbin/sshd -f {sshd_conf()}")
    time.sleep(1)


def stop_servers():
    for name in SERVERS:
        d = f"{WORK}/{name}"
        if not os.path.isdir(d):
            continue
        for fn in os.listdir(d):
            if fn.endswith(".pid"):
                try:
                    os.kill(int(open(f"{d}/{fn}").read().strip()), 15)
                except Exception:
                    pass
                if os.path.exists(f"{d}/{fn}"):
                    os.remove(f"{d}/{fn}")


# ---------------------------------------------------------------- attacks
def loop(inner, d, pause=1):
    """Repeat a command that ends on its own until the episode is over."""
    return f"timeout {d} bash -c {shlex.quote(f'cd {WORK}; while true; do {inner} >/dev/null 2>&1; sleep {pause}; done')}"


def attack_cmd(cls, rng, intensity, dur, size="full"):
    P = PROFILES[size]
    d = int(dur)
    web = rng.choice([ip for ip, _ in SERVERS.values()])
    if cls == "http_flood":
        return web, (f"timeout {d + 5} python3 {HERE}/http_flood.py --target {web} "
                     f"--threads {P['http_threads'][intensity]} --duration {d} "
                     f"--delay {P['http_delay'][intensity]} "
                     f"--mode {'keepalive' if rng.random() < 0.2 else 'new'} "
                     f"--urls {rng.choice(['fixed', 'random'])} --seed {rng.randrange(10**6)}")
    if cls == "slow_dos":
        c, r = P["slow_conns"][intensity], rng.choice([50, 100, 200])
        url = f"http://{web}/p{rng.randrange(200):03d}.html"
        if rng.random() < 0.6:   # slowloris: never-ending headers
            tool = f"slowhttptest -H -c {c} -r {r} -i {rng.choice([5, 10, 15])} -t GET -u {url} -x 24 -p 3 -l {d}"
        else:                    # slow read: reads the response very slowly
            tool = f"slowhttptest -X -c {c} -r {r} -w 512 -y 1024 -n 5 -z 32 -k 3 -u {url} -p 3 -l {d}"
        return web, f"timeout {d} {tool}"
    if cls == "port_scan":
        stype = rng.choice(["-sS", "-sS", "-sT", "-sT", "-sF", "-sX", "-sN", "-sU"])
        ports = "--top-ports 200" if stype == "-sU" else \
            rng.choice(P["scan_ports"])
        return web, loop(f"nmap -Pn -n {stype} {NMAP_TIMING[intensity]} {ports} --max-retries 1 {web}",
                         d, P["scan_pause"])
    if cls == "ssh_brute":
        return SSH_SERVER, loop(f"hydra -I -l labuser -P {WORDS} -t {P['hydra_tasks'][intensity]} "
                                f"ssh://{SSH_SERVER}", d)
    raise ValueError(cls)


def schedule(rng, dur, cls, size="full"):
    """List of (start, end, class) in seconds from capture start, with benign gaps between."""
    if cls == "benign":
        return []
    P = PROFILES[size]
    mixed = cls == "mixed"
    eps, t, queue = [], rng.uniform(30, 45), []
    while True:
        length = rng.uniform(*P["ep_len"]) if mixed else rng.uniform(25, 40)
        if t + length > dur - 20:
            return eps
        if mixed:
            if not queue:  # each round has every attack once, in random order
                queue = ATTACK_CLASSES[:]
                rng.shuffle(queue)
            c = queue.pop()
        else:
            c = cls
        eps.append((t, t + length, c))
        t += length + (rng.uniform(*P["gap"]) if mixed else rng.uniform(20, 30))


# ---------------------------------------------------------------- one run
def run_one(row, outdir):
    from mininet.log import setLogLevel
    setLogLevel("warning")
    rng = random.Random(int(row["seed"]))
    dur = float(row["duration"])
    size = row.get("size", "full")
    os.makedirs(outdir, exist_ok=True)
    make_files(size)

    net, clients, attackers, iface = build_net(row)
    procs, tcpdump = [], None
    labels = {
        "session_id": row["session_id"], "cls": row["cls"], "params": row, "capture_iface": iface,
        "servers": {ip: mac for ip, mac in SERVERS.values()},
        "attackers": [{"cls": c, "name": n, "ip": ip, "mac": mac}
                      for c, (n, ip, mac) in ATTACKERS.items()],
        "clients": [h.IP() for h in clients], "episodes": [],
    }
    try:
        start_servers(net, size)
        tcpdump = subprocess.Popen(
            ["tcpdump", "-i", iface, "-w", f"{outdir}/capture.pcap", "-s", "0", "-U", "-q",
             "-Z", "root"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        t0 = time.time()
        labels["capture_start"] = t0

        server_ips = ",".join(ip for ip, _ in SERVERS.values())
        for i, h in enumerate(clients, 1):
            procs.append(h.popen(
                ["python3", f"{HERE}/benign.py", "--servers", server_ips, "--ssh", SSH_SERVER,
                 "--port", str(5200 + i), "--seed", str(int(row["seed"]) * 100 + i),
                 "--duration", str(dur + 30), "--think", str(row["think_s"])]
                + (["--small"] if size == "small" else []),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))

        for (s, e, cls) in schedule(rng, dur, row["cls"], size):
            time.sleep(max(0, t0 + s - time.time()))
            intensity = rng.choice(["low", "med", "high"])
            target, cmd = attack_cmd(cls, rng, intensity, e - s, size)
            h = attackers[cls]
            ep = {"cls": cls, "start": time.time(), "intensity": intensity, "target": target,
                  "attacker": h.IP(), "cmd": cmd}
            p = h.popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(max(0, t0 + e - time.time()))
            p.terminate()
            h.cmd("pkill -f http_flood.py; pkill -f slowhttptest; pkill -f nmap; pkill -f hydra")
            ep["end"] = time.time()
            labels["episodes"].append(ep)
            print(f"  [{ep['start'] - t0:5.0f}s] {cls} ({intensity}) -> {target}")

        time.sleep(max(0, t0 + dur - time.time()))
        labels["capture_end"] = time.time()
    finally:
        for p in procs:
            p.terminate()
        time.sleep(2)
        if tcpdump:
            tcpdump.terminate()
            tcpdump.wait(timeout=10)
        stop_servers()
        net.stop()
    with open(f"{outdir}/labels.json", "w") as f:
        json.dump(labels, f, indent=2)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan", default="plan.csv")
    ap.add_argument("--session")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--out", default="out")
    ap.add_argument("--duration", type=float, help="override duration (quick test)")
    a = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("Run with sudo.")
    rows = list(csv.DictReader(open(a.plan)))

    if a.all:
        for r in rows:
            if os.path.exists(f"{a.out}/{r['session_id']}/labels.json"):
                continue
            print(f"[{time.strftime('%H:%M:%S')}] {r['session_id']} {r['cls']} {r['topology']}")
            subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run([sys.executable, __file__, "--plan", a.plan, "--out", a.out,
                            "--session", r["session_id"]])
        subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return

    row = next((r for r in rows if r["session_id"] == a.session), None)
    if row is None:
        sys.exit(f"{a.session} not in {a.plan}")
    if a.duration:
        row["duration"] = a.duration
    print(f"Running {row['session_id']}: {row['cls']} on {row['topology']}")
    # Clear leftovers from any earlier crashed run (old interfaces, switches, processes)
    subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    run_one(row, f"{a.out}/{row['session_id']}")
    print("Done.")


if __name__ == "__main__":
    main()
