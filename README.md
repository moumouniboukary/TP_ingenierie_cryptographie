# EC1 – Ingénierie de la cryptographie : travaux pratiques 1 à 3

**Étudiant :** LOARI Moumouni Boukary Génie Informatique, École Polytechnique de Ouagadougou **Enseignant :** Dr. Zakaria Sawadogo – année universitaire 2026–2027

Ce dépôt contient le code, les configurations et les comptes rendus des trois TP du module EC1. 



## Contenu

```
.
├── README.md
├── tp1/                      TP 1  chiffrement authentifié (coffre de fichiers)
│   ├── coffre.py
│   └── test_coffre.py
├── tp2/                      TP 2  PKI à deux niveaux avec OpenSSL
│   ├── racine.cnf
│   ├── inter.cnf
│   └── pki.sh
│   ├── certificats_publics
├── tp3/                      TP 3  TLS mutuel, supervision, renouvellement
│   ├── www.tp.local.conf     configuration nginx (conf.d)
│   ├── surveiller.py
│   ├── renouveler.sh
│   └── renouveler.timer      service + minuteur systemd (variante cron en commentaire)
└── rapports/
    ├── Rapport_TP_EC1_ingenierie_cryptographie.pdf   rapport complet
    ├── CR_TP1.pdf           compte rendu du TP 1
    ├── CR_TP2.pdf           compte rendu du TP 2
    └── CR_TP3.pdf           compte rendu du TP 3
```



## TP 1 – Coffre de fichiers (`tp1/`)

Argon2id dérive une clé maîtresse du mot de passe, HKDF-SHA256 en tire une sous-clé par usage, AES-256-GCM chiffre et authentifie.

Format du fichier : `CFR1` | t, m, p (3 × 4 octets) | sel (16) | nonce (12) | chiffré + étiquette (16). L'en-tête de 44 octets suivi du nom du fichier forme les données associées (AAD) : il est authentifié sans être chiffré. Les paramètres sont stockés dans le fichier, donc on peut durcir `T` et `M` sans casser les anciens fichiers (`rechiffrer`).

Paramètres retenus : `t=4`, `m=256 Mio`, `p=4` (≈ 0,5 s par dérivation sur la machine de test).

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install argon2-cffi cryptography pytest
cd tp1
python coffre.py        # mesure le coût de quatre jeux de paramètres
pytest -q               # 8 tests : 8 passed
```



## TP 2 – PKI à deux niveaux (`tp2/`)

- AC racine : P-384, SHA-384, 10 ans, hors ligne (`pathlen:1`).
- AC intermédiaire : P-256, 5 ans, `pathlen:0`, limitée à `tp.local` par `nameConstraints`.
- Certificats finaux : P-256, 90 jours (serveur `www.tp.local`, clients `alice@tp.local` et `bob@tp.local`).
- Révocation par CRL (une CRL par niveau de la chaîne).

`racine.cnf` et `inter.cnf` sont ceux de l'annexe B du sujet, avec deux ajouts signalés par `AJOUT` dans les fichiers : `unique_subject = no` (nécessaire pour renouveler un certificat de même nom) et la section `ext_client_csr` (nom alternatif repris de la demande, pour Bob).

```bash
mkdir ~/pki && cd ~/pki
cp /chemin/du/depot/tp2/{racine.cnf,inter.cnf,pki.sh} .
chmod +x pki.sh
./pki.sh alice          # construit racine, intermédiaire, serveur et client
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -verify_hostname www.tp.local serveur.crt
```

`pki.sh` **recrée** les dossiers `racine/` et `inter/` avec de nouvelles clés : à lancer dans un dossier vide.

## TP 3 – Canal TLS mutuel, supervision, renouvellement (`tp3/`)

- **nginx** (`tp.conf`) : TLS 1.2 et 1.3 uniquement, suites TLS 1.2 limitées à ECDHE + AEAD, tickets de session désactivés, certificat client obligatoire (`ssl_verify_client on`, profondeur 2), vérification des CRL, HSTS.
- `surveiller.py DOSSIER [--alerte 30] [--critique 7]` : affiche les jours restants de chaque certificat ; code de sortie 0 (OK), 1 (alerte), 2 (critique).
- `renouveler.sh` : renouvelle le certificat du serveur si l'expiration approche (seuil de 30 jours) : nouvelle clé, signature, vérification avant déploiement, archivage de l'ancien, `nginx -t`, rechargement sans coupure, retour automatique à l'ancien certificat en cas d'échec.

Variables de `renouveler.sh` : `PKI_DIR`, `TLS_DIR`, `CN`, `SEUIL_JOURS`, `VALIDITE`, `FORCE`, `NGINX_TEST`, `NGINX_RELOAD`, `SUDO`.

```bash
# surveillance
python3 surveiller.py /etc/nginx/tls; echo "code : $?"

# renouvellement forcé, puis échec simulé (le numéro de série doit rester identique)
export PKI_DIR=$HOME/pki SUDO=sudo
FORCE=1 ./renouveler.sh
FORCE=1 NGINX_TEST=false ./renouveler.sh; echo "code : $?"

# test mutuel
curl --cacert racine/racine.crt --cert bob_chaine.crt --key bob.key https://www.tp.local/
```



## Résultats principaux


| Point vérifié       | Résultat                                                            |
| ------------------- | ------------------------------------------------------------------- |
| Tests du coffre     | 8 tests sur 8 réussis                                               |
| Nom hors `tp.local` | `error 47 permitted subtree violation` à la validation              |
| Certificat révoqué  | `error 23 certificate revoked` ; refusé par nginx (HTTP 400)        |
| TLS 1.3 / TLS 1.2   | Bob accepté (`Verification: OK`), `Bonjour CN=bob@tp.local`         |
| Scan `nmap`         | 13 suites TLS 1.2 dont 6 CBC avant correction ; 3 suites AEAD après |
| Wireshark           | certificat visible en TLS 1.2, invisible en TLS 1.3                 |
| Retour arrière      | même numéro de série avant et après l'échec simulé                  |




## Défaut trouvé pendant le TP 3

Un premier test du retour arrière a montré que l'ancien certificat n'était pas restauré (le script affichait pourtant « retour à l'ancien certificat ») : le dossier d'archive, créé par root en mode 700, était invisible pour un utilisateur ordinaire. Les tests passent désormais par `sudo` et le résultat est vérifié par `cmp`.

## Rapports

Les comptes rendus et le rapport complet se trouvent dans `rapports/` .