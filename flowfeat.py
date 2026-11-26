#!/usr/bin/env python3
"""Flow features with the same definitions as the CIC-IDS2017 CSVs (CICFlowMeter-V3).

Used for: our Mininet pcaps (extract_flows.py), the CIC column mapping (prepare_cic.py),
and the live detector (live_detector.py). One definition everywhere.

Definitions (as in CIC-IDS2017):
  flow        = packets with the same (IP, port, IP, port, protocol), both directions.
                Forward = direction of the first packet.
  flow end    = TCP: both sides sent FIN, or a RST was seen. Any protocol: no packet for
                FLOW_TIMEOUT (120 s), or the flow is older than FLOW_TIMEOUT.
                Late TCP packets of a connection that just closed (e.g. the last ACK)
                are ignored, so they do not become fake 1-3 packet "flows".
                (CICFlowMeter-V3 ends at the first FIN, which creates such fragments.)
  time values = microseconds
  "length"    = TCP/UDP payload bytes (headers not counted)
  std         = sample standard deviation (n - 1), 0 if fewer than 2 values
  rates       = per second; 0 if the flow duration is 0
"""
import math
import socket

import dpkt
import numpy as np

FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
FLOW_TIMEOUT = 120.0  # seconds, same as CIC-IDS2017
CLOSED_GRACE = 5.0    # seconds to ignore late packets of a closed TCP connection

# Model input features (names follow the Python CICFlowMeter style)
FEATURES = [
    "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts", "totlen_fwd_pkts", "totlen_bwd_pkts",
    "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_mean", "fwd_pkt_len_std",
    "bwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_mean", "bwd_pkt_len_std",
    "flow_byts_s", "flow_pkts_s",
    "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
    "fwd_iat_tot", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
    "bwd_iat_tot", "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min",
    "fwd_psh_flags", "fwd_pkts_s", "bwd_pkts_s",
    "pkt_len_min", "pkt_len_max", "pkt_len_mean", "pkt_len_std", "pkt_len_var",
    "fin_flag_cnt", "syn_flag_cnt", "rst_flag_cnt", "psh_flag_cnt", "ack_flag_cnt",
    "urg_flag_cnt", "down_up_ratio", "pkt_size_avg", "fwd_seg_size_avg", "bwd_seg_size_avg",
    "init_fwd_win_byts", "init_bwd_win_byts", "fwd_act_data_pkts",
]
# Identifiers kept for labelling/auditing only. Never model inputs.
META = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol", "timestamp"]


def transform(X):
    """Signed log scaling: shrinks huge ranges (bytes/s, microseconds) before scaling."""
    X = np.asarray(X, dtype=float)
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
    return np.sign(X) * np.log1p(np.abs(X))


def _stats(v):
    """mean, sample std, max, min (all 0 for an empty list)."""
    n = len(v)
    if n == 0:
        return 0.0, 0.0, 0.0, 0.0
    m = sum(v) / n
    sd = math.sqrt(sum((x - m) ** 2 for x in v) / (n - 1)) if n > 1 else 0.0
    return m, sd, float(max(v)), float(min(v))


def _iats(ts):
    return [(ts[i] - ts[i - 1]) * 1e6 for i in range(1, len(ts))]


class Flow:
    __slots__ = ("src", "dst", "sport", "dport", "proto", "start", "last", "fwd_len",
                 "bwd_len", "fwd_ts", "bwd_ts", "all_ts", "flags", "fwd_psh", "win_fwd",
                 "win_bwd", "fwd_data", "fin_fwd", "fin_bwd")

    def __init__(self, ts, src, dst, sport, dport, proto):
        self.src, self.dst, self.sport, self.dport, self.proto = src, dst, sport, dport, proto
        self.start = self.last = ts
        self.fwd_len, self.bwd_len, self.fwd_ts, self.bwd_ts, self.all_ts = [], [], [], [], []
        self.flags = {"F": 0, "S": 0, "R": 0, "P": 0, "A": 0, "U": 0}
        self.fwd_psh = 0
        self.win_fwd = self.win_bwd = -1
        self.fwd_data = 0
        self.fin_fwd = self.fin_bwd = False

    def add(self, ts, fwd, plen, tcp_flags, win):
        self.last = ts
        self.all_ts.append(ts)
        if fwd:
            self.fwd_len.append(plen)
            self.fwd_ts.append(ts)
            if plen > 0:
                self.fwd_data += 1
            if win is not None and self.win_fwd == -1:
                self.win_fwd = win
            if tcp_flags is not None and tcp_flags & PSH:
                self.fwd_psh += 1
        else:
            self.bwd_len.append(plen)
            self.bwd_ts.append(ts)
            if win is not None and self.win_bwd == -1:
                self.win_bwd = win
        if tcp_flags is not None and tcp_flags & FIN:
            if fwd:
                self.fin_fwd = True
            else:
                self.fin_bwd = True
        if tcp_flags is not None:
            for bit, k in ((FIN, "F"), (SYN, "S"), (RST, "R"), (PSH, "P"), (ACK, "A"), (URG, "U")):
                if tcp_flags & bit:
                    self.flags[k] += 1

    def features(self):
        dur_us = (self.last - self.start) * 1e6
        dur_s = dur_us / 1e6
        nf, nb = len(self.fwd_len), len(self.bwd_len)
        sf, sb = float(sum(self.fwd_len)), float(sum(self.bwd_len))
        fm, fsd, fmax, fmin = _stats(self.fwd_len)
        bm, bsd, bmax, bmin = _stats(self.bwd_len)
        am, asd, amax, amin = _stats(self.fwd_len + self.bwd_len)
        im, isd, imax, imin = _stats(_iats(self.all_ts))
        fi = _iats(self.fwd_ts)
        bi = _iats(self.bwd_ts)
        fim, fisd, fimax, fimin = _stats(fi)
        bim, bisd, bimax, bimin = _stats(bi)
        rate = (lambda x: x / dur_s) if dur_s > 0 else (lambda x: 0.0)
        return {
            "src_ip": self.src, "dst_ip": self.dst, "src_port": self.sport,
            "dst_port": self.dport, "protocol": self.proto, "timestamp": self.start,
            "flow_duration": dur_us, "tot_fwd_pkts": nf, "tot_bwd_pkts": nb,
            "totlen_fwd_pkts": sf, "totlen_bwd_pkts": sb,
            "fwd_pkt_len_max": fmax, "fwd_pkt_len_min": fmin, "fwd_pkt_len_mean": fm,
            "fwd_pkt_len_std": fsd, "bwd_pkt_len_max": bmax, "bwd_pkt_len_min": bmin,
            "bwd_pkt_len_mean": bm, "bwd_pkt_len_std": bsd,
            "flow_byts_s": rate(sf + sb), "flow_pkts_s": rate(nf + nb),
            "flow_iat_mean": im, "flow_iat_std": isd, "flow_iat_max": imax, "flow_iat_min": imin,
            "fwd_iat_tot": float(sum(fi)), "fwd_iat_mean": fim, "fwd_iat_std": fisd,
            "fwd_iat_max": fimax, "fwd_iat_min": fimin,
            "bwd_iat_tot": float(sum(bi)), "bwd_iat_mean": bim, "bwd_iat_std": bisd,
            "bwd_iat_max": bimax, "bwd_iat_min": bimin,
            "fwd_psh_flags": self.fwd_psh, "fwd_pkts_s": rate(nf), "bwd_pkts_s": rate(nb),
            "pkt_len_min": amin, "pkt_len_max": amax, "pkt_len_mean": am, "pkt_len_std": asd,
            "pkt_len_var": asd ** 2,
            "fin_flag_cnt": self.flags["F"], "syn_flag_cnt": self.flags["S"],
            "rst_flag_cnt": self.flags["R"], "psh_flag_cnt": self.flags["P"],
            "ack_flag_cnt": self.flags["A"], "urg_flag_cnt": self.flags["U"],
            "down_up_ratio": float(nb // nf) if nf else 0.0,
            "pkt_size_avg": (sf + sb) / (nf + nb), "fwd_seg_size_avg": fm, "bwd_seg_size_avg": bm,
            "init_fwd_win_byts": self.win_fwd, "init_bwd_win_byts": self.win_bwd,
            "fwd_act_data_pkts": self.fwd_data,
        }


class FlowTable:
    """Feed packets with add(ts, raw_ethernet_bytes). Finished flows go to on_flow(dict)."""

    def __init__(self, on_flow, timeout=FLOW_TIMEOUT):
        self.on_flow, self.timeout = on_flow, timeout
        self.flows = {}
        self.closed = {}  # key -> time the TCP connection closed
        self.n = 0

    def _key(self, a, ap, b, bp, proto):
        return (a, ap, b, bp, proto) if (a, ap) <= (b, bp) else (b, bp, a, ap, proto)

    def add(self, ts, buf):
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                return
            l4 = ip.data
            if isinstance(l4, dpkt.tcp.TCP):
                proto, flags, win = 6, l4.flags, l4.win
                plen = max(ip.len - ip.hl * 4 - l4.off * 4, 0)
            elif isinstance(l4, dpkt.udp.UDP):
                proto, flags, win = 17, None, None
                plen = max(l4.ulen - 8, 0)
            else:
                return
            src, dst = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)
            sp, dp = l4.sport, l4.dport
        except Exception:
            return
        k = self._key(src, sp, dst, dp, proto)
        f = self.flows.get(k)
        if f is not None and (ts - f.last > self.timeout or ts - f.start > self.timeout):
            self._end(k)
            f = None
        if f is None:
            c = self.closed.get(k)
            is_syn = flags is not None and flags & SYN and not flags & ACK
            if c is not None and ts - c < CLOSED_GRACE and not is_syn:
                return  # leftover packet of a connection that already closed
            f = self.flows[k] = Flow(ts, src, dst, sp, dp, proto)
        f.add(ts, (src, sp) == (f.src, f.sport), plen, flags, win)
        if flags is not None and (flags & RST or (f.fin_fwd and f.fin_bwd)):
            self._end(k)
            self.closed[k] = ts
        self.n += 1
        if self.n % 20000 == 0:
            self.expire(ts, self.timeout)
            self.closed = {k: t for k, t in self.closed.items() if ts - t < CLOSED_GRACE}

    def _end(self, k):
        f = self.flows.pop(k, None)
        if f is not None:
            self.on_flow(f.features())

    def expire(self, now, idle):
        """End flows with no packets for `idle` seconds (or older than the timeout)."""
        for k in [k for k, f in self.flows.items()
                  if now - f.last > idle or now - f.start > self.timeout]:
            self._end(k)

    def snapshot_old(self, now, min_age):
        """Features of still-open flows older than min_age (live use only, flow not ended)."""
        return [f.features() for f in self.flows.values() if now - f.start >= min_age]

    def flush(self):
        for k in list(self.flows):
            self._end(k)
