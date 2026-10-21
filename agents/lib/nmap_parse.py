#!/usr/bin/env python3
"""Convertit la sortie XML de nmap en TSV pour discover.sh.

Colonnes : ip, ports_ouverts (séparés par ,), ttl, famille_os, nom_os, vendeur_mac
"""
import sys
import xml.etree.ElementTree as ET


def main(path):
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError) as exc:
        print(f"ERR|lecture XML nmap impossible : {exc}", file=sys.stderr)
        return 1

    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        ip, vendor = "", ""
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr", "")
            elif addr.get("addrtype") == "mac":
                vendor = addr.get("vendor", "")
        if not ip:
            continue

        ttl = int(status.get("reason_ttl") or 0)
        ports = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            ports.append(port.get("portid"))
            if not ttl:
                ttl = int(state.get("reason_ttl") or 0)

        family, name = "", ""
        match = host.find("os/osmatch")
        if match is not None:
            name = match.get("name", "")
            osclass = match.find("osclass")
            if osclass is not None:
                family = osclass.get("osfamily", "")

        print("\t".join([ip, ",".join(ports), str(ttl), family, name, vendor]).replace("\n", " "))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "/dev/stdin"))
