#!/usr/bin/env bash
# One-time setup. Works on Kali Linux (and Debian/Ubuntu).
# Use a VM: this creates a test user 'labuser' with a known password.
set -e
export DEBIAN_FRONTEND=noninteractive

sudo apt update
# Mininet itself is skipped if it is already installed.
dpkg -s mininet >/dev/null 2>&1 || sudo -E apt install -y mininet
sudo -E apt install -y openvswitch-switch nmap tcpdump nginx dnsmasq-base iperf3 curl \
  bind9-dnsutils openssh-server sshpass hydra slowhttptest \
  python3-dpkt python3-pandas python3-numpy python3-sklearn python3-matplotlib

# Stop system copies of the servers. Our own copies run inside the Mininet hosts.
sudo systemctl disable --now nginx 2>/dev/null || true
sudo systemctl disable --now iperf3 2>/dev/null || true
sudo systemctl enable --now openvswitch-switch

# SSH host keys (Kali sometimes has none) and the sshd runtime folder
sudo ssh-keygen -A
sudo mkdir -p /run/sshd

# Test user for SSH (benign logins + brute force target), used only inside Mininet.
sudo useradd -m -s /bin/bash labuser 2>/dev/null || true
echo 'labuser:Lab@2026pass' | sudo chpasswd
# Block this user on the machine's real SSH server, in case you ever turn it on.
sudo mkdir -p /etc/ssh/sshd_config.d
echo 'DenyUsers labuser' | sudo tee /etc/ssh/sshd_config.d/99-deny-labuser.conf >/dev/null

echo
echo "Checks:"
sudo python3 -c "import mininet, dpkt, pandas, sklearn, matplotlib; print('  python packages OK')"
echo "Now test Mininet with:  sudo mn --test pingall"
