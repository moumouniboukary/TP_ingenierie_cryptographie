#!/usr/bin/env bash
# pki.sh - construit la PKI du TP 2 (racine, intermediaire, serveur, client).
# Usage : ./pki.sh [client]   (client par defaut : alice)
# A lancer dans le dossier contenant racine.cnf et inter.cnf.
set -euo pipefail

CLIENT="${1:-alice}"
SUBJ_BASE="/C=BF/O=Universite TP"

init_ca() {   # $1 = dossier de l'AC
  mkdir -p "$1/newcerts" "$1/crl"
  : > "$1/index.txt"
  echo 1000 > "$1/serial"
  echo 1000 > "$1/crlnumber"
}

# --- Etape 2 : AC racine (P-384, 10 ans) ---------------------------------
init_ca racine
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out racine/racine.key
chmod 600 racine/racine.key
openssl req -x509 -new -key racine/racine.key -sha384 -days 3650 \
  -subj "$SUBJ_BASE/CN=Racine TP" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" \
  -out racine/racine.crt

# --- Etape 3 : AC intermediaire (P-256, 5 ans) ---------------------------
init_ca inter
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out inter/inter.key
chmod 600 inter/inter.key
openssl req -new -key inter/inter.key -subj "$SUBJ_BASE/CN=Intermediaire TP" -out inter/inter.csr
openssl ca -batch -notext -config racine.cnf -extensions ext_inter -days 1825 \
  -in inter/inter.csr -out inter/inter.crt

# --- Etape 4 : serveur et client (P-256, 90 jours) -----------------------
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out serveur.key
openssl req -new -key serveur.key -subj "/CN=www.tp.local" \
  -addext "subjectAltName=DNS:www.tp.local,DNS:tp.local" -out serveur.csr
openssl ca -batch -notext -config inter.cnf -extensions ext_serveur -days 90 \
  -in serveur.csr -out serveur.crt

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$CLIENT.key"
openssl req -new -key "$CLIENT.key" -subj "/CN=$CLIENT@tp.local" \
  -addext "subjectAltName=email:$CLIENT@tp.local" -out "$CLIENT.csr"
openssl ca -batch -notext -config inter.cnf -extensions ext_client_csr -days 90 \
  -in "$CLIENT.csr" -out "$CLIENT.crt"

chmod 600 serveur.key "$CLIENT.key"
echo "PKI construite : racine/racine.crt inter/inter.crt serveur.crt $CLIENT.crt"
