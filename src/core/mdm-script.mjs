import { parseEvery } from './schedule-plan.mjs';

export const MDM_OSES = ['macos', 'linux', 'windows'];
export const PACKAGE_NAME = '@shomra/agent';

const shQuote = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;
const psQuote = (s) => `'${String(s).replace(/'/g, "''")}'`;

function bashScript({ os, key, url, hours }) {
  const jamf = os === 'macos';
  const keyLine = key
    ? `SHOMRA_API_KEY="\${SHOMRA_API_KEY:-}"\n[ -n "$SHOMRA_API_KEY" ] || SHOMRA_API_KEY=${shQuote(key)}`
    : `SHOMRA_API_KEY="\${SHOMRA_API_KEY:-${jamf ? '${4:-}' : ''}}"`;
  const urlLine = url
    ? `SHOMRA_URL="\${SHOMRA_URL:-}"\n[ -n "$SHOMRA_URL" ] || SHOMRA_URL=${shQuote(url)}`
    : `SHOMRA_URL="\${SHOMRA_URL:-${jamf ? '${5:-}' : ''}}"`;
  return `#!/bin/bash
# Shomra endpoint agent - MDM bootstrap (${os}). Run as root.${jamf ? '\n# Jamf: pass the API key as parameter 4 and the URL as parameter 5, or set SHOMRA_API_KEY / SHOMRA_URL.' : ''}
set -euo pipefail

${keyLine}
${urlLine}
if [ -z "$SHOMRA_API_KEY" ]; then echo "SHOMRA_API_KEY is not set - supply it from your MDM's secret variables" >&2; exit 1; fi
if [ -z "$SHOMRA_URL" ]; then echo "SHOMRA_URL is not set" >&2; exit 1; fi
if [ "$(id -u)" -ne 0 ]; then echo "run this as root" >&2; exit 1; fi
export SHOMRA_API_KEY SHOMRA_URL

export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:\${PATH:-}"
NODE="$(command -v node || true)"
if [ -z "$NODE" ]; then echo "Node.js 18+ is required - deploy it first" >&2; exit 1; fi
NPM="$(dirname "$NODE")/npm"
PREFIX=/usr/local/shomra
ENTRY="$PREFIX/lib/node_modules/${PACKAGE_NAME}/shomra.mjs"

if [ ! -f "$ENTRY" ]; then
  umask 022
  "$NPM" install --global --prefix "$PREFIX" ${PACKAGE_NAME}
fi

"$NODE" "$ENTRY" init --machine --url "$SHOMRA_URL"
"$NODE" "$ENTRY" schedule install --all-users --every ${hours}h
"$NODE" "$ENTRY" report --all-users || echo "first report finished with findings or errors - see the Shomra dashboard"
exit 0
`;
}

function powershellScript({ key, url, hours }) {
  return `# Shomra endpoint agent - MDM bootstrap (Windows). Run as SYSTEM or an elevated Administrator.
$ErrorActionPreference = 'Stop'

$ApiKey = $env:SHOMRA_API_KEY
${key ? `if (-not $ApiKey) { $ApiKey = ${psQuote(key)} }\n` : ''}$Url = $env:SHOMRA_URL
${url ? `if (-not $Url) { $Url = ${psQuote(url)} }\n` : ''}if (-not $ApiKey) { Write-Error "SHOMRA_API_KEY is not set - supply it from your MDM's secret variables"; exit 1 }
if (-not $Url) { Write-Error 'SHOMRA_URL is not set'; exit 1 }
$env:SHOMRA_API_KEY = $ApiKey
$env:SHOMRA_URL = $Url

$Node = (Get-Command node.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
if (-not $Node) {
  $Candidate = Join-Path $env:ProgramFiles 'nodejs\\node.exe'
  if (Test-Path $Candidate) { $Node = $Candidate }
}
if (-not $Node) { Write-Error 'Node.js 18+ is required - deploy it first'; exit 1 }
$Npm = Join-Path (Split-Path $Node) 'npm.cmd'
$Prefix = Join-Path $env:ProgramFiles 'Shomra'
$Entry = Join-Path $Prefix 'node_modules\\${PACKAGE_NAME.replace('/', '\\')}\\shomra.mjs'

if (-not (Test-Path $Entry)) {
  & $Npm install --global --prefix $Prefix ${PACKAGE_NAME}
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

& $Node $Entry init --machine --url $Url
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $Node $Entry schedule install --all-users --every ${hours}h
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $Node $Entry report --all-users
if ($LASTEXITCODE -ne 0) { Write-Output 'first report finished with findings or errors - see the Shomra dashboard' }
exit 0
`;
}

export function mdmScript({ os, key = null, url = null, every = undefined } = {}) {
  const target = String(os ?? '').toLowerCase();
  if (!MDM_OSES.includes(target)) throw new Error(`--os must be one of ${MDM_OSES.join(', ')}`);
  const hours = parseEvery(every);
  const args = { os: target, key: key && key !== true ? String(key) : null, url: url && url !== true ? String(url).replace(/\/$/, '') : null, hours };
  return target === 'windows' ? powershellScript(args) : bashScript(args);
}
