#!/bin/sh
set -eu
# Keep the certificate across image upgrades. Pages distributes this public trust anchor.
cd /app/tls
if ! openssl x509 -in cert.pem -noout -checkend 2592000 >/dev/null 2>&1; then
    umask 077
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
        -subj "/CN=CORE sticker importer" -addext "subjectAltName=IP:${STICKER_IP:?}" \
        -addext "extendedKeyUsage=serverAuth" -keyout next.key -out next.crt
    mv next.key key.pem
    mv next.crt cert.pem
fi
cd /app
exec gunicorn --bind 0.0.0.0:8080 --workers 2 --timeout 75 \
    --certfile /app/tls/cert.pem --keyfile /app/tls/key.pem service:app
