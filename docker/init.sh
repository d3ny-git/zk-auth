#!/bin/sh
# One-shot initialisation for docker compose (idempotent: reuses /data).
#   /data/keys     trusted setup (pk.bin, vk.bin, vk.json, manifest.json)
#   /data/issuer   issuer tree with 20 dummies + a demo credential, roots.json
#   /demo          demo cred.json + path.json, bind-mounted to ./demo on the host
set -eu
if [ ! -f /data/keys/pk.bin ]; then
    echo "init: running the (single-party, demo-only) trusted setup…"
    zkauth-setup --out /data/keys
fi
if [ ! -f /data/issuer/issuer.json ]; then
    echo "init: creating the issuer tree with 20 dummy credentials…"
    zkauth-issuer init --state /data/issuer --dummies 20
    zkauth-issuer new --state /data/issuer --dob 2001-05-14 --out /demo/cred.json
    zkauth-issuer root --state /data/issuer --roots-out /data/issuer/roots.json
    zkauth-issuer path --state /data/issuer --index 20 --out /demo/path.json
    chmod 644 /demo/cred.json /demo/path.json
fi
mkdir -p /data/server && chown 10001 /data/server  # the server runs as uid 10001
echo "init: done. Open http://localhost:8080 and load demo/cred.json + demo/path.json"
