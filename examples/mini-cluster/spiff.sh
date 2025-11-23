#!/bin/sh
# Generate a SPIFFE-style X.509 workload certificate signed by an existing CA.
# Trust domain: nanocloud.io
#
# Usage:
#   ./generate-spiffe-cert.sh <common-name>
#
# Inputs (must already exist):
#   /var/lib/nanocloud.io/secure_assets/ca.key
#   /var/lib/nanocloud.io/secure_assets/ca.crt
#
# Outputs (in ./certs):
#   <CN>-key.pem, <CN>-cert.pem, <CN>.csr, <CN>-chain.pem
#
# Optional environment overrides:
#   SPIFFE_PATH=/ns/default/sa/<cn>
#   CERT_DAYS=90

set -eu

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <common-name>" >&2
  exit 1
fi

CN="$1"
OUT_DIR="certs"
SPIFFE_TRUST_DOMAIN="nanocloud.io"
SPIFFE_PATH="${SPIFFE_PATH:-/ns/default/sa/${CN}}"
CERT_DAYS="${CERT_DAYS:-90}"

CA_DIR="/var/lib/nanocloud.io/secure_assets"
CA_KEY="${CA_DIR}/ca.key"
CA_CERT="${CA_DIR}/ca.crt"

SPIFFE_URI="spiffe://${SPIFFE_TRUST_DOMAIN}${SPIFFE_PATH}"

# ---- validation ----
for f in "${CA_KEY}" "${CA_CERT}"; do
  [ -f "$f" ] || {
    echo "Missing CA file: $f" >&2
    exit 1
  }
done

command -v openssl >/dev/null 2>&1 || {
  echo "openssl not found on PATH" >&2
  exit 1
}

umask 077
mkdir -p "${OUT_DIR}"

TMPDIR="$(mktemp -d)"
cleanup() { rm -rf "${TMPDIR}"; }
trap cleanup EXIT INT TERM

# ---- workload config ----
cat > "${TMPDIR}/workload.cnf" <<EOF
[ req ]
distinguished_name = dn
req_extensions     = v3_ext
prompt             = no

[ dn ]
CN = ${CN}

[ v3_ext ]
subjectAltName   = URI:${SPIFFE_URI}
keyUsage         = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectKeyIdentifier = hash
EOF

KEY_FILE="${OUT_DIR}/${CN}-key.pem"
CSR_FILE="${OUT_DIR}/${CN}.csr"
CERT_FILE="${OUT_DIR}/${CN}-cert.pem"
CHAIN_FILE="${OUT_DIR}/${CN}-chain.pem"

# ---- key + CSR ----
openssl ecparam -name prime256v1 -genkey -noout -out "${KEY_FILE}"
openssl req -new -key "${KEY_FILE}" \
  -config "${TMPDIR}/workload.cnf" -out "${CSR_FILE}"

# ---- sign with existing CA ----
openssl x509 -req -in "${CSR_FILE}" \
  -CA "${CA_CERT}" -CAkey "${CA_KEY}" -CAcreateserial \
  -days "${CERT_DAYS}" -extfile "${TMPDIR}/workload.cnf" -extensions v3_ext \
  -out "${CERT_FILE}"

# ---- assemble chain ----
cat "${CERT_FILE}" "${CA_CERT}" > "${CHAIN_FILE}"

# ---- summary ----
echo ""
echo "Generated SPIFFE workload certificate"
echo "  Trust domain : ${SPIFFE_TRUST_DOMAIN}"
echo "  SPIFFE ID    : ${SPIFFE_URI}"
echo "  Common Name  : ${CN}"
echo "  Output dir   : ${OUT_DIR}"
echo ""
echo "Files:"
echo "  Key   : ${KEY_FILE}"
echo "  Cert  : ${CERT_FILE}"
echo "  Chain : ${CHAIN_FILE}"
echo ""
echo "Inspect with:"
echo "  openssl x509 -in ${CERT_FILE} -noout -text | grep -A3 'Subject Alternative'"
