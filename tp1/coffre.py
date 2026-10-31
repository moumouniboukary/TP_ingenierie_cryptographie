"""coffre.py - Mini-coffre de fichiers (TP 1, EC1 Ingenierie de la cryptographie).

Format du fichier chiffre (version CFR1) :

    offset  taille  champ
    0       4       identifiant de format  b"CFR1"
    4       4       T  (temps Argon2id)        entier non signe, gros-boutiste
    8       4       M  (memoire en Kio)        entier non signe, gros-boutiste
    12      4       P  (parallelisme)          entier non signe, gros-boutiste
    16      16      sel Argon2id
    32      12      nonce AES-GCM
    44      ...     chiffre + etiquette (16 octets)

Les 44 premiers octets (en-tete) suivis du nom du fichier forment les donnees
associees (AAD) : authentifiees mais non chiffrees.

Aucune primitive n'est reimplementee : Argon2id (argon2-cffi), HKDF-SHA256 et
AES-GCM (cryptography).
"""
import os
import struct

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"CFR1"
TAILLE_SEL = 16
TAILLE_NONCE = 12
TAILLE_ENTETE = 4 + 12 + TAILLE_SEL + TAILLE_NONCE  # 44
TAILLE_ETIQUETTE = 16

# Parametres par defaut : temps, memoire (Kio), parallelisme.
# Mesures sur la machine de TP (Kali VM) : (t=4, m=256 Mio, p=4) ~ 0,47 s.
T, M, P = 4, 256 * 1024, 4


class FormatInconnu(ValueError):
    """Identifiant de format ou structure d'en-tete non reconnu(e)."""


def cle_maitresse(mot_de_passe: str, sel: bytes, t: int = T, m: int = M, p: int = P) -> bytes:
    """Argon2id -> 32 octets."""
    return hash_secret_raw(
        secret=mot_de_passe.encode("utf-8"),
        salt=sel,
        time_cost=t,
        memory_cost=m,
        parallelism=p,
        hash_len=32,
        type=Type.ID,
    )


def sous_cle(maitresse: bytes, usage: bytes) -> bytes:
    """HKDF-SHA256 avec info = b"coffre-v1|" + usage -> 32 octets."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"coffre-v1|" + usage,
    ).derive(maitresse)


def _construire_entete(t: int, m: int, p: int, sel: bytes, nonce: bytes) -> bytes:
    entete = MAGIC + struct.pack(">III", t, m, p) + sel + nonce
    assert len(entete) == TAILLE_ENTETE
    return entete


def _lire_entete(blob: bytes):
    if len(blob) < TAILLE_ENTETE + TAILLE_ETIQUETTE:
        raise FormatInconnu("fichier trop court")
    if blob[:4] != MAGIC:
        raise FormatInconnu("identifiant de format inconnu")
    t, m, p = struct.unpack(">III", blob[4:16])
    sel = blob[16:32]
    nonce = blob[32:44]
    return t, m, p, sel, nonce


def _aad(entete: bytes, nom: str) -> bytes:
    return entete + nom.encode("utf-8")


def chiffrer(mot_de_passe: str, nom: str, donnees: bytes) -> bytes:
    """Chiffre `donnees` ; `nom` est lie au chiffre via les donnees associees."""
    sel = os.urandom(TAILLE_SEL)
    nonce = os.urandom(TAILLE_NONCE)
    entete = _construire_entete(T, M, P, sel, nonce)
    cle = sous_cle(cle_maitresse(mot_de_passe, sel, T, M, P), b"chiffrement")
    corps = AESGCM(cle).encrypt(nonce, donnees, _aad(entete, nom))
    return entete + corps


def dechiffrer(mot_de_passe: str, nom: str, blob: bytes) -> bytes:
    """Dechiffre ; leve InvalidTag en cas d'echec d'authentification."""
    t, m, p, sel, nonce = _lire_entete(blob)
    entete = blob[:TAILLE_ENTETE]
    cle = sous_cle(cle_maitresse(mot_de_passe, sel, t, m, p), b"chiffrement")
    return AESGCM(cle).decrypt(nonce, blob[TAILLE_ENTETE:], _aad(entete, nom))


def rechiffrer(ancien_mdp: str, nouveau_mdp: str, nom: str, blob: bytes) -> bytes:
    """Change le mot de passe (et remonte aux parametres courants)."""
    return chiffrer(nouveau_mdp, nom, dechiffrer(ancien_mdp, nom, blob))


def mesurer_parametres(t: int = T, m: int = M, p: int = P) -> float:
    """Duree (s) d'une derivation Argon2id avec ces parametres."""
    import time

    debut = time.perf_counter()
    cle_maitresse("mesure", os.urandom(TAILLE_SEL), t, m, p)
    return time.perf_counter() - debut


if __name__ == "__main__":
    for (t, m, p) in [(1, 32 * 1024, 4), (2, 64 * 1024, 4), (3, 64 * 1024, 4), (3, 128 * 1024, 4)]:
        print(f"t={t} m={m // 1024} Mio p={p} : {mesurer_parametres(t, m, p):.3f} s")
