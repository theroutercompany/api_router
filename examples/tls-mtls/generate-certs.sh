#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="$(dirname "$0")/certs"
mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

# CA
openssl req -x509 -newkey rsa:2048 -days 365 -nodes \
  -keyout ca-key.pem -out ca.pem \
  -subj "/CN=api-router-ca"

# Server cert
openssl req -newkey rsa:2048 -nodes \
  -keyout server-key.pem -out server.csr \
  -subj "/CN=127.0.0.1"
openssl x509 -req -in server.csr -days 365 -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
  -out server.pem -extensions req_ext -extfile <(cat <<EOT
[req_ext]
subjectAltName = IP:127.0.0.1
EOT
)

# Client cert
openssl req -newkey rsa:2048 -nodes \
  -keyout client-key.pem -out client.csr \
  -subj "/CN=api-router-client"
openssl x509 -req -in client.csr -days 365 -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
  -out client.pem

rm -f server.csr client.csr
chmod 600 *-key.pem

echo "Certificates written to $OUT_DIR"
