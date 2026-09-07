#!/usr/bin/env sh
set -eu

VERSION="${VERSION:-latest}"
PROTECT="${PROTECT:-true}"
RULES="${RULES:-false}"

if ! command -v node >/dev/null 2>&1; then
  echo "[shomra] Node is not present in this image. Add the Node feature (or a Node base image) before this one." >&2
  echo "[shomra]   \"ghcr.io/devcontainers/features/node:1\": {}" >&2
  exit 1
fi

echo "[shomra] installing @shomra/agent@${VERSION}"
npm install -g "@shomra/agent@${VERSION}"

mkdir -p /usr/local/share/shomra
cat > /usr/local/share/shomra/post-create.sh <<POSTCREATE
#!/usr/bin/env sh
set -u

echo "[shomra] \$(shomra --version 2>/dev/null || echo 'not on PATH')"

if [ "${PROTECT}" = "true" ]; then
  shomra protect || echo "[shomra] protect failed (non-fatal) - run 'shomra protect' by hand"
fi

if [ "${RULES}" = "true" ]; then
  shomra rules --write || echo "[shomra] rules --write failed (non-fatal)"
fi

shomra doctor || true
POSTCREATE
chmod +x /usr/local/share/shomra/post-create.sh

echo "[shomra] installed; protect=${PROTECT} rules=${RULES}"
