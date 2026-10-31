#!/usr/bin/env python3
"""surveiller.py - supervision des dates d'expiration des certificats d'un dossier.

Usage : surveiller.py DOSSIER [--alerte 30] [--critique 7]

Niveaux : OK, ALERTE (< 30 jours), CRITIQUE (< 7 jours, ou deja expire).
Code de sortie : 0 (tout OK), 1 (au moins une ALERTE), 2 (au moins un CRITIQUE),
utilisable directement par Nagios/Icinga/Zabbix ou un minuteur systemd.
"""
import argparse
import datetime as dt
import pathlib
import sys

from cryptography import x509

EXTENSIONS = {".crt", ".pem", ".cer"}


def lire_certificats(chemin: pathlib.Path):
    """Rend la liste des certificats PEM d'un fichier (un fichier peut contenir une chaine)."""
    try:
        return x509.load_pem_x509_certificates(chemin.read_bytes())
    except ValueError:
        return []  # pas un certificat PEM (CRL, cle privee, ...) : ignore


def niveau(jours: int, alerte: int, critique: int):
    if jours < critique:
        return "CRITIQUE", 2
    if jours < alerte:
        return "ALERTE", 1
    return "OK", 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("dossier", type=pathlib.Path)
    ap.add_argument("--alerte", type=int, default=30, help="seuil ALERTE en jours")
    ap.add_argument("--critique", type=int, default=7, help="seuil CRITIQUE en jours")
    args = ap.parse_args(argv)

    if not args.dossier.is_dir():
        print(f"UNKNOWN : {args.dossier} n'est pas un dossier", file=sys.stderr)
        return 3

    maintenant = dt.datetime.now(dt.timezone.utc)
    pire = 0
    trouves = 0
    for fichier in sorted(args.dossier.iterdir()):
        if fichier.suffix.lower() not in EXTENSIONS or not fichier.is_file():
            continue
        for i, cert in enumerate(lire_certificats(fichier)):
            trouves += 1
            reste = cert.not_valid_after_utc - maintenant
            jours = reste.days  # arrondi vers le bas ; negatif si expire
            etat, code = niveau(jours, args.alerte, args.critique)
            pire = max(pire, code)
            cn = cert.subject.rfc4514_string()
            suffixe = f"#{i}" if i else ""
            print(f"{etat:<8} {jours:>5} j  {fichier.name}{suffixe}  [{cn}]  "
                  f"expire le {cert.not_valid_after_utc:%Y-%m-%d}")
    if trouves == 0:
        print("Aucun certificat trouve", file=sys.stderr)
    return pire


if __name__ == "__main__":
    sys.exit(main())
