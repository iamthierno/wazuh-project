#!/usr/bin/env python3
"""Simulateur d'agent Wazuh (laboratoire de test).

Fait apparaître un agent Windows ou macOS sur le manager, sans machine réelle :
enrôlement auprès d'authd (1515, mot de passe, groupe), puis connexion chiffrée
au port 1514 (protocole agent : zlib + AES-256-CBC, en-tête "!<id>!#AES:"),
keepalives et envoi d'événements réalistes (journaux Windows EventChannel,
journaux macOS) décrits dans un fichier de scénario JSON.

Inspiré du simulateur officiel wazuh-qa (deps/wazuh_testing/tools/agent_simulator.py),
réduit au strict nécessaire et sans dépendance autre que `cryptography`.

Exemple :
  WAZUH_ENROLL_PASS=... ./wazuh_agent_sim.py --manager 192.168.1.5 --name WIN-SRV01 \
      --os windows-server-2022 --group windows --scenario scenarios/windows.json --duration 120
"""
import argparse
import hashlib
import json
import os
import random
import socket
import ssl
import struct
import sys
import threading
import time
import zlib

from cryptography.hazmat.primitives import padding as sympad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

VERSION = "v4.14.9"

# Chaîne « uname » envoyée dans le keepalive : c'est elle qui donne l'OS affiché par le dashboard
UNAMES = {
    "windows-server-2022": "Microsoft Windows Server 2022 Datacenter [Ver: 10.0.20348.2655]",
    "windows-11": "Microsoft Windows 11 Pro [Ver: 10.0.22631.4317]",
    "windows-10": "Microsoft Windows 10 Enterprise [Ver: 10.0.19045.5011]",
    "macos-14": "Darwin |{host} |23.6.0 |Darwin Kernel Version 23.6.0: Mon Jul 29 21:14:30 PDT 2024; "
                "root:xnu-10063.141.2~1/RELEASE_ARM64_T6000 |arm64 [macOS|darwin: 14.6.1 (Sonoma)]",
    "macos-15": "Darwin |{host} |24.1.0 |Darwin Kernel Version 24.1.0: Thu Oct 10 21:02:27 PDT 2024; "
                "root:xnu-11215.41.3~2/RELEASE_X86_64 |x86_64 [macOS|darwin: 15.1 (Sequoia)]",
}

MQ_LOCALFILE = "1"
MQ_EVENTCHANNEL = "f"


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


class SimAgent:
    def __init__(self, manager, name, os_key, group, password, ip):
        self.manager, self.name, self.os_key, self.group = manager, name, os_key, group
        self.password, self.ip = password, ip
        self.id = self.key = None
        self.sock = None
        self.lock = threading.Lock()
        self.global_counter = int(time.time())   # croissant : anti-rejeu de remoted
        self.local_counter = 0
        self.sent = 0

    # ------------------------------------------------------------ enrôlement
    def enroll(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = "OSSEC "
        if self.password:
            req += f"PASS: {self.password} OSSEC "
        req += f"A:'{self.name}'"
        if self.group:
            req += f" G:'{self.group}'"
        with socket.create_connection((self.manager, 1515), timeout=15) as raw:
            with ctx.wrap_socket(raw, server_hostname=self.manager) as s:
                s.sendall((req + "\n").encode())
                ans = s.recv(4096).decode(errors="replace")
        if "OSSEC K:'" not in ans:
            raise RuntimeError(f"enrôlement refusé : {ans.strip()}")
        self.id, _name, _ip, self.key = ans.split("'")[1].split(" ")
        log(f"{self.name} : enrôlé (ID {self.id}, groupe {self.group})")

    # ------------------------------------------------------------ chiffrement
    def _aes_key(self):
        s1 = hashlib.md5(hashlib.md5(self.name.encode()).hexdigest().encode()
                         + hashlib.md5(self.id.encode()).hexdigest().encode()).hexdigest()[:15]
        s2 = hashlib.md5(self.key.encode()).hexdigest()
        return (s2 + s1).encode()[:32]

    def _build(self, message):
        self.global_counter += 1
        self.local_counter = (self.local_counter + 1) % 10000
        head = f"{random.randint(0, 65535):05d}{self.global_counter % 10**10:010d}:{self.local_counter:04d}:"
        body = head.encode() + message.encode()
        event = hashlib.md5(body).hexdigest().encode() + body
        comp = zlib.compress(event)
        extra = len(comp) % 8
        comp = b"!" * (8 - extra if extra else 8) + comp
        padder = sympad.PKCS7(128).padder()
        data = padder.update(comp) + padder.finalize()
        enc = Cipher(algorithms.AES(self._aes_key()), modes.CBC(b"FEDCBA0987654321")).encryptor()
        payload = enc.update(data) + enc.finalize()
        return f"!{self.id}!#AES:".encode() + payload

    def send(self, message):
        frame = self._build(message)
        with self.lock:
            for attempt in range(3):
                try:
                    self.sock.sendall(struct.pack("<I", len(frame)) + frame)
                    self.sent += 1
                    return
                except OSError:
                    time.sleep(2)
                    self._open()
            raise ConnectionError("connexion au manager perdue")

    # ------------------------------------------------------------ session
    def _open(self):
        if self.sock:
            self.sock.close()
        self.sock = socket.create_connection((self.manager, 1514), timeout=15)
        self.sock.settimeout(None)
        threading.Thread(target=self._drain, daemon=True).start()

    def connect(self):
        self._open()
        self.send("#!-agent startup ")
        self.keepalive()

    def _drain(self):
        # Les messages du manager (fichiers partagés, commandes) sont lus et ignorés
        try:
            while self.sock.recv(65536):
                pass
        except OSError:
            pass

    def keepalive(self):
        uname = UNAMES[self.os_key].format(host=self.name)
        msg = (f"#!-{uname} - Wazuh {VERSION} / ab73af41699f13fdd81903b5f23d8d00\n"
               f"ab73af41699f13fdd81903b5f23d8d00 merged.mg\n")
        if self.ip:
            msg += f'#"_agent_ip":{self.ip}\n'
        self.send(msg)

    # ------------------------------------------------------------ événements
    def windows_event(self, ev):
        data = "".join(f"<Data Name='{k}'>{v}</Data>" for k, v in ev.get("data", {}).items())
        now = time.strftime("%Y-%m-%dT%H:%M:%S.000000000Z", time.gmtime())
        xml = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
               f"<Provider Name='{ev['provider']}' Guid='{{{ev.get('guid', '54849625-5478-4994-a5ba-3e3b0328c30d')}}}'/>"
               f"<EventID>{ev['id']}</EventID><Version>{ev.get('version', 0)}</Version><Level>{ev.get('level', 0)}</Level>"
               f"<Task>{ev.get('task', 0)}</Task><Opcode>0</Opcode><Keywords>{ev.get('keywords', '0x8020000000000000')}</Keywords>"
               f"<TimeCreated SystemTime='{now}'/><EventRecordID>{random.randint(10000, 999999)}</EventRecordID>"
               "<Correlation/><Execution ProcessID='700' ThreadID='800'/>"
               f"<Channel>{ev['channel']}</Channel><Computer>{self.name}.corp.local</Computer><Security/>"
               f"</System><EventData>{data}</EventData></Event>")
        self.send(f"{MQ_EVENTCHANNEL}:EventChannel:" + json.dumps({"Message": ev.get("message", ""), "Event": xml}))

    def syslog_event(self, ev):
        stamp = time.strftime("%b %d %H:%M:%S")
        line = ev["line"].replace("{host}", self.name)
        self.send(f"{MQ_LOCALFILE}:{ev.get('location', '/var/log/system.log')}:{stamp} {self.name} {line}")

    def play(self, scenario):
        for ev in scenario:
            for _ in range(int(ev.get("repeat", 1))):
                if ev["type"] == "windows":
                    self.windows_event(ev)
                else:
                    self.syslog_event(ev)
                time.sleep(float(ev.get("interval", 0.3)))
            log(f"{self.name} : {ev.get('label', ev['type'])} ×{ev.get('repeat', 1)}")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--manager", required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--os", choices=sorted(UNAMES), required=True)
    p.add_argument("--group", default="")
    p.add_argument("--ip", default="", help="IP déclarée de l'agent (affichage)")
    p.add_argument("--scenario", help="fichier JSON d'événements à rejouer")
    p.add_argument("--duration", type=int, default=60, help="durée de présence (s) après le scénario")
    p.add_argument("--id", help="ID existant (évite un nouvel enrôlement)")
    p.add_argument("--key", help="clé existante (avec --id)")
    a = p.parse_args()

    agent = SimAgent(a.manager, a.name, a.os, a.group, os.environ.get("WAZUH_ENROLL_PASS", ""), a.ip)
    try:
        if a.id and a.key:
            agent.id, agent.key = a.id, a.key
        else:
            agent.enroll()
            time.sleep(12)  # le manager recharge client.keys périodiquement (≈10 s)
        agent.connect()
    except Exception as exc:  # noqa: BLE001
        log(f"{a.name} : ÉCHEC {exc}")
        return 1
    log(f"{a.name} : connecté au manager {a.manager}:1514 ({a.os})")
    time.sleep(5)
    if a.scenario:
        with open(a.scenario, encoding="utf-8") as fh:
            agent.play(json.load(fh))
    end = time.time() + a.duration
    while time.time() < end:
        time.sleep(10)
        agent.keepalive()
    log(f"{a.name} : {agent.sent} messages envoyés, arrêt")
    return 0


if __name__ == "__main__":
    sys.exit(main())
