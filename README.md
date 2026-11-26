# ML-Based Network Intrusion Detection with a Self-Built Mininet Dataset

A complete pipeline for flow-based network intrusion detection:

1. **Dataset generation** in Mininet: benign users and four attack types, fully labelled.
2. **Flow features** that follow the CIC-IDS2017 definitions (50 features per flow).
3. **Models**: a Random Forest baseline, an MLP trained from scratch, and an MLP pre-trained on CIC-IDS2017 and fine-tuned on the Mininet data.
4. **Live detector**: classifies traffic in real time, blocks attackers with OpenFlow drop rules and shows everything on a web dashboard.

| Result | Value |
| --- | --- |
| Macro-F1 on an unseen Mininet topology (Model A) | 0.989 ± 0.008 |
| Benign false positive rate (Model A) | 0.0% |
| Macro-F1 on CIC-IDS2017 (Model A / fine-tuned B-60) | 0.168 / 0.792 |
| Live demo: attacks detected with correct type | 5 of 5 |
| Live demo: median time to block | 1.2 s |
| Live demo: successful user requests during attacks | 84.4% without detector, 99.6% with detector |
| Live demo: legitimate users blocked | 0 |

---

## Classes

| Class | Attack tool | Similar CIC-IDS2017 label |
| --- | --- | --- |
| benign | curl, dig, ping, iperf3, ssh (scripted users) | BENIGN |
| http_flood | `http_flood.py` (HTTP GET flood) | DoS Hulk |
| slow_dos | slowhttptest (slowloris, slow read) | DoS slowloris, DoS Slowhttptest |
| port_scan | nmap (SYN, connect, FIN, Xmas, NULL, UDP) | PortScan |
| ssh_brute | hydra | SSH-Patator |

## Repository structure

```
.
├── README.md
├── requirements.txt              Python packages for the notebook
├── setup.sh                      One-time setup on Kali Linux (tools, packages, test SSH user)
├── make_plan.py                  Writes plan.csv: one row per capture run
├── plan.csv                      The plan used for the published dataset
├── run_session.py                Builds the Mininet network, runs benign users and attacks, captures traffic
├── benign.py                     Benign user behaviour (runs inside each client host)
├── http_flood.py                 HTTP GET flood tool
├── flowfeat.py                   Flow construction + 50 CIC-IDS2017-style features (shared by dataset and live detector)
├── extract_flows.py              Capture files -> labelled flows (dataset/flows.csv)
├── extract_windows.py            Optional: time-window features (not used by the final models)
├── check_dataset.py              Class counts, constant features, quick Random Forest check
├── ids_training.ipynb            CIC-IDS2017 preparation, training, evaluation, figures, model export
├── live_detector.py              Live detection, blocking, dashboard server, baseline comparison
├── dashboard.html                Live dashboard page
├── dataset/
│   ├── flows.csv                 Final dataset: 60,464 labelled flows
│   └── labels/                   labels.json of each capture run (episodes, attackers, settings)
├── models/
│   └── detector.npz              Deployed model (Model A, seed 0), NumPy format
└── results/
    ├── B60/                      Notebook results, 60 fine-tuning epochs
    ├── B200/                     Notebook results, 200 fine-tuning epochs
    └── demo/                     Live demo summaries and dashboard screenshots
```

Raw packet captures (`out/*/capture.pcap`, about 1 GB) and the CIC-IDS2017 files are **not** included. The captures can be regenerated with the scripts. CIC-IDS2017 is available from the [Canadian Institute for Cybersecurity](https://www.unb.ca/cic/datasets/ids-2017.html).

## The dataset

`dataset/flows.csv` has one row per flow.

| Column(s) | Meaning | Used as model input? |
| --- | --- | --- |
| 50 feature columns (`flow_duration` ... `fwd_act_data_pkts`) | Flow statistics. Times in microseconds, lengths in payload bytes, sample standard deviation (same definitions as CIC-IDS2017) | Yes |
| `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `timestamp` | Flow identifiers | No (identifiers only) |
| `label` | One of the 5 classes | Target |
| `session_id` | Capture run (S001 to S004) | No (used for splitting) |
| `topology`, `split_group` | Run topology; `main` (S001 to S003) or `heldout` (S004) | No (used for splitting) |

| Class | main (S001 to S003) | heldout (S004) | Total |
| --- | --- | --- | --- |
| benign | 7,166 | 1,752 | 8,918 |
| http_flood | 15,218 | 1,413 | 16,631 |
| port_scan | 26,415 | 5,248 | 31,663 |
| slow_dos | 2,501 | 320 | 2,821 |
| ssh_brute | 330 | 101 | 431 |
| **Total** | **51,630** | **8,834** | **60,464** |

**Labelling rule.** Each attacker host runs exactly one attack type and sends nothing else. A flow with an attacker IP on either side gets that attacker's class. All other flows are benign.

**Flow rule.** A TCP flow ends when both sides have sent FIN, or on RST. Any flow ends after 120 s idle or at 120 s age. Packets arriving after a connection has closed are ignored.

---

## Requirements

- **Dataset generation and live demo:** Kali Linux (or Debian/Ubuntu) in a virtual machine, 4 vCPU, 8 GB RAM, 5 GB free disk.
- **Training:** any machine with Python 3.10 or newer. A GPU is optional.

> Use a virtual machine. `setup.sh` creates a local test user (`labuser`) with a known password for the SSH brute force experiments. It is blocked on the machine's real SSH server.

## 1. Setup (Kali Linux)

```bash
git clone https://github.com/<your-username>/<repo-name>.git
cd <repo-name>
bash setup.sh
sudo mn --test pingall          # should report 0% dropped
```

## 2. Generate the dataset (about 45 minutes)

```bash
python3 make_plan.py                       # 4 runs x 10 min (small profile)
sudo python3 run_session.py --all          # captures out/S001 ... out/S004
sudo chown -R $USER:$USER out
python3 extract_flows.py                   # -> dataset/flows.csv
python3 check_dataset.py dataset/flows.csv
```

Quick test of one short run before the full capture:

```bash
sudo python3 run_session.py --session S001 --duration 180
```

## 3. Train and evaluate

```bash
pip install -r requirements.txt
```

1. Put `dataset/flows.csv` next to the notebook.
2. Put these CIC-IDS2017 *MachineLearningCSV* files in `cic/`:
   `Monday-WorkingHours.pcap_ISCX.csv`, `Tuesday-WorkingHours.pcap_ISCX.csv`,
   `Wednesday-workingHours.pcap_ISCX.csv`, `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`
3. Open `ids_training.ipynb` and run all cells.

Outputs: `results/summary.csv`, `results/per_class_recall.csv`, `results/per_seed.csv`, figures in `results/`, and the exported model `models/detector.npz`.

| Model | Description |
| --- | --- |
| RF | Random Forest, 200 trees, balanced class weights (baseline) |
| A | MLP 50 → 128 → 64 → 5, trained from scratch on the Mininet data |
| P | Same MLP, trained on CIC-IDS2017 only |
| B | P fine-tuned on the Mininet data, learning rate 1e-4 (B-60: 60 epochs, B-200: 200 epochs) |

## 4. Live detection demo (Kali Linux)

Copy `models/detector.npz` into `models/`, then:

```bash
sudo python3 live_detector.py --mode baseline    # no protection
sudo python3 live_detector.py --mode detect      # with the detector
```

Open **http://localhost:8080** in Firefox while it runs. Both modes use the same seed, so the same attacks start at the same times. The detect run prints a comparison with the baseline at the end. Press Ctrl+C to close the dashboard.

How the detector works:

1. tcpdump streams packets from the server uplink (`s99-eth1`).
2. `flowfeat.py` builds flows with the same 50 features used in training.
3. New flows are classified once per second.
4. An IP is blocked when at least 5 of its flows in the last 10 s are attacks and they make up at least 60% of its flows.
5. The block is an OpenFlow drop rule on every switch, removed after 120 s. Open connections from that IP are closed on the servers.

Useful options: `--min-flows`, `--min-frac`, `--window`, `--block-secs`, `--nginx-conns`, `--allow`.

## Results summary

| Model | Mininet test (S004) macro-F1 | CIC-IDS2017 test macro-F1 |
| --- | --- | --- |
| RF | 0.994 ± 0.005 | 0.289 ± 0.040 |
| A (scratch) | 0.989 ± 0.008 | 0.168 ± 0.012 |
| P (CIC only) | 0.146 ± 0.073 | 0.982 ± 0.001 |
| B-60 (fine-tuned) | 0.938 ± 0.018 | 0.792 ± 0.004 |
| B-200 (fine-tuned) | 0.975 ± 0.021 | 0.616 ± 0.041 |

Models trained on one network do not transfer to the other. Fine-tuning a CIC-pre-trained model on the Mininet data gives the best balance. Longer fine-tuning improves the Mininet score but causes catastrophic forgetting of CIC-IDS2017.

## Troubleshooting

| Problem | Fix |
| --- | --- |
| `RTNETLINK answers: File exists` | `sudo mn -c`, then run again |
| `FileNotFoundError: plan.csv` | Run `python3 make_plan.py` first |
| A run stopped part way | Run `sudo python3 run_session.py --all` again; finished runs are skipped |
| Notebook shows `Device: cpu` | Fine for this data size; install a CUDA build of PyTorch to use an NVIDIA GPU |

## References

- Sharafaldin, I., Habibi Lashkari, A. and Ghorbani, A. A. (2018). Toward generating a new intrusion detection dataset and intrusion traffic characterization. ICISSP.
- Engelen, G., Rimmer, V. and Joosen, W. (2021). Troubleshooting an intrusion detection dataset: the CICIDS2017 case study. IEEE SPW.
- Lantz, B., Heller, B. and McKeown, N. (2010). A network in a laptop: rapid prototyping for software-defined networks. HotNets.

## Author

[Your Name], Master of Computer Science, University of New Brunswick. Machine learning course project, 2026.
