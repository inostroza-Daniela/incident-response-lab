#!/usr/bin/env bash
# Genera los certificados internos del laboratorio con OpenSSL, sin depender de
# descargas en tiempo de ejecución. Los nombres, el directorio y los DN coinciden
# con lo que esperan el docker-compose y config/wazuh/indexer/wazuh.indexer.yml.
# Credenciales y certificados de uso exclusivo en laboratorio aislado.
set -euo pipefail

DIR="$(cd "$(dirname "$0")/.." && pwd)/config/wazuh/certs"
SUBJ="/C=US/L=California/O=Wazuh/OU=Wazuh"
DIAS=3650

mkdir -p "$DIR"
cd "$DIR"

# Autoridad certificadora raíz: firma el resto de los certificados.
openssl req -x509 -newkey rsa:2048 -nodes -days "$DIAS" -sha256 \
  -keyout root-ca.key -out root-ca.pem -subj "$SUBJ/CN=root-ca" 2>/dev/null

# Genera un certificado de nodo firmado por la CA raíz.
#   $1 nombre del nodo (y CN)   $2 extensiones x509v3
_nodo() {
  local nombre="$1" ext="$2"
  openssl req -newkey rsa:2048 -nodes -keyout "${nombre}-key.pem" \
    -out "${nombre}.csr" -subj "$SUBJ/CN=${nombre}" -sha256 2>/dev/null
  openssl x509 -req -in "${nombre}.csr" -CA root-ca.pem -CAkey root-ca.key \
    -CAcreateserial -days "$DIAS" -sha256 -out "${nombre}.pem" \
    -extfile <(printf '%s\n' "$ext") 2>/dev/null
  rm -f "${nombre}.csr"
}

EXT_NODO="subjectAltName=DNS:%s
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth"

for nodo in wazuh.indexer wazuh.manager wazuh.dashboard; do
  # shellcheck disable=SC2059
  _nodo "$nodo" "$(printf "$EXT_NODO" "$nodo")"
done

# Certificado de administrador del indexer (cliente): DN = admin_dn del opensearch.yml.
_nodo admin "basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth"

chmod 644 ./*.pem ./*.key
rm -f root-ca.srl

echo "Certificados generados en $DIR"
ls -1 "$DIR"
