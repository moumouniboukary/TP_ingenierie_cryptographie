import os

import pytest
from cryptography.exceptions import InvalidTag

import coffre

# Parametres allegés pour accelerer les tests (le format les relit dans l'en-tete).
coffre.T, coffre.M, coffre.P = 1, 8 * 1024, 1

MDP = "correct cheval pile agrafe"
NOM = "releve.txt"
DONNEES = b"solde = 1 250 000 FCFA\n" * 10


def test_aller_retour():
    blob = coffre.chiffrer(MDP, NOM, DONNEES)
    assert coffre.dechiffrer(MDP, NOM, blob) == DONNEES


def test_chiffrement_probabiliste():
    a = coffre.chiffrer(MDP, NOM, DONNEES)
    b = coffre.chiffrer(MDP, NOM, DONNEES)
    assert a != b
    assert a[16:32] != b[16:32]  # sels differents
    assert a[32:44] != b[32:44]  # nonces differents


def test_mauvais_mot_de_passe():
    blob = coffre.chiffrer(MDP, NOM, DONNEES)
    with pytest.raises(InvalidTag):
        coffre.dechiffrer("mauvais mot de passe", NOM, blob)


def test_octet_modifie():
    blob = bytearray(coffre.chiffrer(MDP, NOM, DONNEES))
    blob[coffre.TAILLE_ENTETE + 5] ^= 0x01
    with pytest.raises(InvalidTag):
        coffre.dechiffrer(MDP, NOM, bytes(blob))


def test_entete_modifie():
    blob = bytearray(coffre.chiffrer(MDP, NOM, DONNEES))
    blob[20] ^= 0x01  # un octet du sel
    with pytest.raises(InvalidTag):
        coffre.dechiffrer(MDP, NOM, bytes(blob))


def test_nom_echange():
    blob = coffre.chiffrer(MDP, "a.txt", DONNEES)
    with pytest.raises(InvalidTag):
        coffre.dechiffrer(MDP, "b.txt", blob)


def test_format_inconnu():
    blob = b"XXXX" + coffre.chiffrer(MDP, NOM, DONNEES)[4:]
    with pytest.raises(coffre.FormatInconnu):
        coffre.dechiffrer(MDP, NOM, blob)


def test_rechiffrer_et_evolution_des_parametres():
    # Ancien fichier produit avec des parametres faibles ...
    coffre.T, coffre.M, coffre.P = 1, 8 * 1024, 1
    ancien = coffre.chiffrer(MDP, NOM, DONNEES)
    # ... l'application passe a des parametres plus forts.
    coffre.T, coffre.M, coffre.P = 2, 16 * 1024, 2
    # L'ancien fichier reste lisible (parametres relus dans l'en-tete).
    assert coffre.dechiffrer(MDP, NOM, ancien) == DONNEES
    nouveau = coffre.rechiffrer(MDP, "nouveau mot de passe", NOM, ancien)
    assert coffre.dechiffrer("nouveau mot de passe", NOM, nouveau) == DONNEES
    assert nouveau[4:16] != ancien[4:16]  # nouveaux parametres dans l'en-tete
    with pytest.raises(InvalidTag):
        coffre.dechiffrer(MDP, NOM, nouveau)
    coffre.T, coffre.M, coffre.P = 1, 8 * 1024, 1
