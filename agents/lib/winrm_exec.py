#!/usr/bin/env python3
"""Exécution PowerShell distante sur Windows via WinRM (PowerShell Remoting).

Utilisé par install-agent.sh. Le mot de passe est lu dans la variable
d'environnement WZ_WIN_PASS (jamais sur la ligne de commande).

  winrm_exec.py --host IP --user USER [--https] [--port N] [--auth ntlm]
                [--no-verify] (--check | --script FICHIER | --copy SRC DEST)

Codes retour : 0 = OK, 2 = connexion impossible, 3 = authentification refusée,
               4 = erreur d'exécution, 5 = module pypsrp absent
"""
import argparse
import os
import sys

try:
    from pypsrp.client import Client
    from pypsrp.exceptions import AuthenticationError, WinRMTransportError
except ImportError:  # pragma: no cover
    print("WINRM_ERROR|module python 'pypsrp' absent (pip install pypsrp)", file=sys.stderr)
    sys.exit(5)

import requests.exceptions


def build_client(args):
    port = args.port or (5986 if args.https else 5985)
    return Client(
        args.host,
        port=port,
        username=args.user,
        password=os.environ.get("WZ_WIN_PASS", ""),
        ssl=args.https,
        auth=args.auth,
        cert_validation=not args.no_verify,
        connection_timeout=args.timeout,
        operation_timeout=max(args.timeout, 20),
        read_timeout=max(args.timeout, 20) + 10,
        encryption="never" if args.auth == "basic" else "auto",
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", required=True)
    p.add_argument("--user", required=True)
    p.add_argument("--port", type=int)
    p.add_argument("--https", action="store_true")
    p.add_argument("--auth", default="negotiate", choices=["negotiate", "ntlm", "kerberos", "credssp", "basic"])
    p.add_argument("--no-verify", action="store_true", help="ne pas vérifier le certificat HTTPS")
    p.add_argument("--timeout", type=int, default=10)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true", help="teste la connexion et les identifiants")
    g.add_argument("--script", help="script PowerShell à exécuter")
    g.add_argument("--copy", nargs=2, metavar=("SRC", "DEST"), help="copie un fichier vers la cible")
    args = p.parse_args()

    try:
        client = build_client(args)
        if args.check:
            out, _streams, _err = client.execute_ps("$env:COMPUTERNAME")
            print(f"WINRM_OK|{out.strip()}")
            return 0
        if args.copy:
            client.copy(args.copy[0], args.copy[1])
            print("WINRM_OK|copie terminée")
            return 0
        with open(args.script, encoding="utf-8-sig") as fh:
            script = fh.read()
        out, streams, had_errors = client.execute_ps(script)
        if out:
            print(out.rstrip())
        if had_errors and "RESULT|" not in (out or ""):
            for err in streams.error:
                print(f"ERR|{err}", file=sys.stderr)
            return 4
        return 0
    except AuthenticationError as exc:
        print(f"WINRM_ERROR|authentification refusée ({exc})", file=sys.stderr)
        return 3
    except WinRMTransportError as exc:
        code = getattr(exc, "code", None)
        if code == 401:
            print("WINRM_ERROR|authentification refusée (401)", file=sys.stderr)
            return 3
        print(f"WINRM_ERROR|erreur WinRM ({exc})", file=sys.stderr)
        return 2
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
        print(f"WINRM_ERROR|connexion impossible ({exc.__class__.__name__})", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001
        print(f"WINRM_ERROR|{exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(main())
