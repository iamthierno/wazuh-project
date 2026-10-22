#!/usr/bin/env python3
"""Équipements réseau simulés (laboratoire) : envoi syslog UDP avec une IP
source distincte par équipement, comme en production.

Chaque ligne de devices.csv associe une IP source (alias posé sur l'interface
du réseau Docker par lab.sh) à un fichier d'échantillons de
network-devices/samples/. Modes :
  --mode samples  : chaque échantillon une fois par équipement
  --mode attack   : rafales réalistes (brute force VPN/admin, balayages)
  --mode load     : charge soutenue (--eps événements/s pendant --duration s)
Le compteur d'envois est affiché pour comparer avec ce que le manager a reçu.
"""
import argparse
import csv
import os
import socket
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SAMPLES = os.path.join(ROOT, "network-devices", "samples")

# Lignes d'échantillon rejouées en rafale pour simuler une attaque (index 0-based)
ATTACK = {
    "fortigate": [(0, 10)],     # échecs SSL VPN -> 100100
    "paloalto": [(1, 10), (3, 25)],   # échecs admin -> 100111 ; refus -> 100113
    "cisco-asa": [(0, 10)],     # AAA rejeté -> 100121
    "cisco-ftd": [(0, 10)],     # AAA rejeté -> 100124
    "juniper-srx": [(0, 25)],   # refus -> 100132
    "mikrotik": [(0, 10), (1, 1)],    # brute force puis succès -> 100142, 100265
    "sophos-xg": [(1, 10)],     # échecs d'auth -> 100151
    "pfsense": [(0, 20)],       # blocages -> 87702
    "cisco-ios": [(0, 10)],
}


def load_devices(path):
    devs = []
    with open(path, encoding="utf-8") as fh:
        for row in csv.reader(line for line in fh if line.strip() and not line.startswith("#")):
            ip, sample = row[0].strip(), row[1].strip()
            with open(os.path.join(SAMPLES, sample + ".log"), encoding="utf-8") as sf:
                lines = [l.rstrip("\n") for l in sf if l.strip()]
            devs.append((ip, sample, lines))
    return devs


def sender(ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((ip, 0))
    return s


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--manager", required=True, help="IP du conteneur manager (réseau wazuh_default)")
    p.add_argument("--port", type=int, default=514)
    p.add_argument("--devices", default=os.path.join(os.path.dirname(__file__), "devices.csv"))
    p.add_argument("--mode", choices=["samples", "attack", "load"], default="samples")
    p.add_argument("--eps", type=int, default=500)
    p.add_argument("--duration", type=int, default=30)
    a = p.parse_args()

    devs = load_devices(a.devices)
    socks = {ip: sender(ip) for ip, _, _ in devs}
    dest = (a.manager, a.port)
    sent = 0

    if a.mode == "samples":
        for ip, sample, lines in devs:
            for line in lines:
                socks[ip].sendto(line.encode(), dest)
                sent += 1
                time.sleep(0.02)
            print(f"{ip:15} {sample:12} {len(lines)} échantillon(s)")
    elif a.mode == "attack":
        for ip, sample, lines in devs:
            for idx, count in ATTACK.get(sample, []):
                for _ in range(count):
                    socks[ip].sendto(lines[idx].encode(), dest)
                    sent += 1
                    time.sleep(0.05)
            print(f"{ip:15} {sample:12} rafale envoyée")
    else:
        flat = [(socks[ip], line.encode()) for ip, _, lines in devs for line in lines]
        interval = 1.0 / a.eps
        end = time.time() + a.duration
        nxt = time.time()
        i = 0
        while time.time() < end:
            s, payload = flat[i % len(flat)]
            s.sendto(payload, dest)
            sent += 1
            i += 1
            nxt += interval
            delay = nxt - time.time()
            if delay > 0:
                time.sleep(delay)
        print(f"charge : {sent} messages en {a.duration} s (cible {a.eps} EPS, réel {sent / a.duration:.0f} EPS)")
    print(f"TOTAL_SENT={sent}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
