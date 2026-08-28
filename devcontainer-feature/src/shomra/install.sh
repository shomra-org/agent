#!/usr/bin/env sh
# Dev Container Feature installer for Shomra.
#
# Why this exists: a control the developer has to remember to install is a
# control that covers the developers who already know they need it. Provisioning
# is the one moment where coverage is total and nobody had to opt in.
#
# Runs at IMAGE BUILD time, as root, with the feature's options in the
# environment (VERSION / PROTECT / RULES). Deliberately does the minimum here -
# `shomra protect` has to run against the WORKSPACE and the user's own agent
# configs, neither of which exist yet at build time, so it is deferred to
# postCreateCommand via the script this drops.
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
# Runs once, as the container user, after the workspace is mounted - which is
# what makes it able to see the agent configs and the repo. Every step is
# best-effort: a security tool that stops a dev container from coming up will be
# removed from the dev container.
set -u

echo "[shomra] \$(shomra --version 2>/dev/null || echo 'not on PATH')"

if [ "${PROTECT}" = "true" ]; then
  shomra protect || echo "[shomra] protect failed (non-fatal) - run 'shomra protect' by hand"
fi

if [ "${RULES}" = "true" ]; then
  shomra rules --write || echo "[shomra] rules --write failed (non-fatal)"
fi

# Always tell the developer where they stand, even when nothing was wired.
shomra doctor || true
POSTCREATE
chmod +x /usr/local/share/shomra/post-create.sh

echo "[shomra] installed; protect=${PROTECT} rules=${RULES}"
