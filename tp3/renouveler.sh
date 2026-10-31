#!/usr/bin/env bash
# renouveler.sh - renouvelle le certificat du serveur s'il expire bientot.
#
# Etapes : nouvelle cle + CSR -> signature par l'intermediaire -> verification de la
# chaine -> sauvegarde de l'ancien -> installation -> nginx -t -> reload (sans coupure).
# En cas d'echec apres installation, l'ancien certificat est remis en place.
#
# Variables (valeurs par defaut entre parentheses) :
#   PKI_DIR  (/srv/pki)        dossier contenant racine.cnf, inter.cnf, racine/, inter/
#   TLS_DIR  (/etc/nginx/tls)  dossier lu par nginx
#   CN       (www.tp.local)    nom du serveur
#   SEUIL_JOURS (30)  VALIDITE (90)  FORCE (0 : renouveler meme si le seuil n'est pas atteint)
#   NGINX_TEST ("nginx -t")   NGINX_RELOAD ("systemctl reload nginx")   SUDO ("" ou "sudo")
set -euo pipefail
umask 077

PKI_DIR="${PKI_DIR:-/srv/pki}"
TLS_DIR="${TLS_DIR:-/etc/nginx/tls}"
CN="${CN:-www.tp.local}"
SEUIL_JOURS="${SEUIL_JOURS:-30}"
VALIDITE="${VALIDITE:-90}"
FORCE="${FORCE:-0}"
NGINX_TEST="${NGINX_TEST:-nginx -t}"
NGINX_RELOAD="${NGINX_RELOAD:-systemctl reload nginx}"
SUDO="${SUDO:-}"

log() { echo "$(date -u +%FT%TZ) renouveler: $*"; }

CHAINE_ACTUELLE="$TLS_DIR/serveur_chaine.crt"

# 0. Renouveler seulement si necessaire. -checkend echoue si le certificat
#    (le premier du fichier, donc la feuille) expire dans moins de N secondes.
if [ "$FORCE" != "1" ] && [ -f "$CHAINE_ACTUELLE" ] \
   && openssl x509 -checkend $((SEUIL_JOURS * 86400)) -noout -in "$CHAINE_ACTUELLE" >/dev/null; then
  log "certificat valide encore plus de $SEUIL_JOURS jours : rien a faire"
  exit 0
fi

# Le PID evite toute collision si deux executions tombent dans la meme seconde
# (une archive ne doit jamais en ecraser une autre).
horodatage="$(date -u +%Y%m%dT%H%M%SZ)-$$"
travail="$PKI_DIR/renouvellements/$horodatage"
archive="$TLS_DIR/archive/$horodatage"
mkdir -p "$travail"
cd "$PKI_DIR"

# 1. Nouvelle cle privee et nouvelle demande
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$travail/serveur.key"
openssl req -new -key "$travail/serveur.key" -subj "/CN=$CN" \
  -addext "subjectAltName=DNS:$CN,DNS:tp.local" -out "$travail/serveur.csr"

# 2. Signature par l'intermediaire
openssl ca -batch -notext -config inter.cnf -extensions ext_serveur -days "$VALIDITE" \
  -in "$travail/serveur.csr" -out "$travail/serveur.crt" >/dev/null 2>&1

# 3. Verification AVANT tout deploiement : chaine, nom, usage, et cle correspondant au certificat
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -verify_hostname "$CN" -purpose sslserver "$travail/serveur.crt"
pub_cert="$(openssl x509 -in "$travail/serveur.crt" -noout -pubkey)"
pub_cle="$(openssl pkey -in "$travail/serveur.key" -pubout)"
if [ "$pub_cert" != "$pub_cle" ]; then
  log "ERREUR : la cle ne correspond pas au certificat, abandon"; exit 1
fi
cat "$travail/serveur.crt" inter/inter.crt > "$travail/serveur_chaine.crt"

# 5 (avant 4). Conserver l'ancien pour pouvoir revenir en arriere
if [ -f "$CHAINE_ACTUELLE" ]; then
  $SUDO mkdir -p "$archive"
  $SUDO cp -p "$TLS_DIR/serveur.key" "$TLS_DIR/serveur_chaine.crt" "$archive/"
fi

restaurer() {
  log "ECHEC : tentative de retour a l'ancien certificat ($archive)"
  # Le dossier d'archive appartient a root (mode 700 a cause de umask 077) :
  # tous les tests passent par $SUDO, sinon un utilisateur ordinaire ne voit rien.
  if $SUDO test -f "$archive/serveur_chaine.crt" && $SUDO test -f "$archive/serveur.key"; then
    $SUDO install -m 600 "$archive/serveur.key" "$TLS_DIR/serveur.key"
    $SUDO install -m 644 "$archive/serveur_chaine.crt" "$TLS_DIR/serveur_chaine.crt"
    # On verifie le resultat au lieu de le supposer.
    if $SUDO cmp -s "$archive/serveur_chaine.crt" "$TLS_DIR/serveur_chaine.crt" \
       && $SUDO cmp -s "$archive/serveur.key" "$TLS_DIR/serveur.key"; then
      log "ancien certificat remis en place"
    else
      log "ERREUR GRAVE : la restauration n'a pas abouti, intervention manuelle necessaire"
    fi
  else
    log "ERREUR GRAVE : pas d'archive exploitable, restauration impossible"
  fi
}

# 4. Installation, test de configuration, rechargement sans interruption
$SUDO install -m 600 "$travail/serveur.key" "$TLS_DIR/serveur.key"
$SUDO install -m 644 "$travail/serveur_chaine.crt" "$TLS_DIR/serveur_chaine.crt"

if ! $SUDO $NGINX_TEST; then restaurer; exit 1; fi
if ! $SUDO $NGINX_RELOAD; then restaurer; $SUDO $NGINX_RELOAD || true; exit 1; fi

fin="$(openssl x509 -in "$TLS_DIR/serveur_chaine.crt" -noout -enddate | cut -d= -f2)"
log "certificat renouvele, valable jusqu'au $fin (ancien conserve dans $archive)"
