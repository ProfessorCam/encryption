#!/bin/sh
set -e

mkdir -p /certs

# Generate a fresh self-signed RSA cert on each start.
if [ ! -f /certs/server.key ] || [ ! -f /certs/server.crt ]; then
  echo "[https-demo] Generating self-signed RSA-2048 certificate..."
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    -keyout /certs/server.key \
    -out /certs/server.crt
fi

# Start with an empty key log; sessions get appended as clients connect.
: > /certs/keylog.txt

exec python3 /app/server.py
