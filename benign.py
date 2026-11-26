#!/usr/bin/env python3
"""Benign user traffic. Runs inside one Mininet client host.

Each loop picks a random activity, then waits a random 'think time'.
Activities: web browsing, file download, DNS lookups, ping, iperf3 TCP/UDP, parallel page burst,
SSH logins (normal ones, and sometimes a mistyped password).
"""
import argparse
import random
import subprocess
import time

p = argparse.ArgumentParser()
p.add_argument("--servers", required=True, help="comma separated server IPs")
p.add_argument("--dns", default="10.0.0.101")
p.add_argument("--ssh", default="10.0.0.101")
p.add_argument("--port", type=int, required=True, help="this client's iperf3 port")
p.add_argument("--seed", type=int, default=1)
p.add_argument("--duration", type=float, default=300)
p.add_argument("--think", type=float, default=1.0, help="mean think time in seconds")
p.add_argument("--small", action="store_true", help="smaller downloads and transfers")
a = p.parse_args()

rng = random.Random(a.seed)
servers = a.servers.split(",")
fav = rng.choice(servers)  # each user prefers one server


def run(cmd, timeout):
    try:
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=timeout)
    except subprocess.TimeoutExpired:
        pass


def srv():
    return fav if rng.random() < 0.7 else rng.choice(servers)


def page(s):
    return f"http://{s}/p{rng.randrange(200):03d}.html"


def web():
    s = srv()
    urls = " ".join(page(s) for _ in range(rng.randint(1, 6)))
    run(f"curl -s -o /dev/null {urls}", 20)


def download():
    rate = rng.choice(["100k", "200k", "300k"] if a.small else ["200k", "500k", "1M", "2M"])
    secs = rng.randint(2, 6) if a.small else rng.randint(5, 20)
    run(f"curl -s -o /dev/null --limit-rate {rate} --max-time {secs} "
        f"http://{srv()}/big{rng.randint(1, 5)}.bin", 25)


def dns():
    for _ in range(rng.randint(1, 5)):
        run(f"dig +short +time=1 +tries=1 @{a.dns} name{rng.randrange(1000)}.lab", 3)


def ping():
    run(f"ping -c {rng.randint(2, 8)} -i 0.5 {srv()}", 10)


def iperf_tcp():
    t, b = (rng.randint(1, 3), rng.choice(["200K", "500K", "1M"])) if a.small else \
        (rng.randint(2, 8), rng.choice(["500K", "2M", "5M"]))
    run(f"iperf3 -c {srv()} -p {a.port} -t {t} -b {b}", 15)


def iperf_udp():
    t, b = (rng.randint(1, 3), rng.choice(["100K", "300K", "500K"])) if a.small else \
        (rng.randint(2, 6), rng.choice(["100K", "500K", "2M"]))
    run(f"iperf3 -u -c {srv()} -p {a.port} -t {t} -b {b}", 12)


def burst():
    # Like a browser opening many connections at once. Makes benign traffic harder to
    # separate from a low-rate HTTP flood.
    s = srv()
    urls = " ".join(page(s) for _ in range(rng.randint(5, 15) if a.small else rng.randint(10, 40)))
    run(f"curl -s -Z --parallel-max {rng.randint(10, 30)} -o /dev/null {urls}", 20)


SSH_CMDS = ["ls -la", "uptime", "cat /etc/hostname", "df -h", "ps aux | head",
            "head -c 200000 /dev/urandom | base64 | wc -c"]


def ssh():
    # 10% of logins use a wrong password first, like a real user mistyping it.
    opts = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"
    if rng.random() < 0.1:
        run(f"sshpass -p wrongpass ssh {opts} labuser@{a.ssh} true", 10)
    run(f"sshpass -p 'Lab@2026pass' ssh {opts} labuser@{a.ssh} '{rng.choice(SSH_CMDS)}'", 15)


ACTIONS = [web, download, dns, ping, iperf_tcp, iperf_udp, burst, ssh]
WEIGHTS = [33, 3, 14, 5, 9, 9, 7, 10] if a.small else [33, 8, 14, 5, 9, 9, 7, 10]

end = time.time() + a.duration
time.sleep(rng.uniform(0, 3))  # clients do not all start at once
while time.time() < end:
    rng.choices(ACTIONS, WEIGHTS)[0]()
    time.sleep(rng.expovariate(1.0 / a.think))
