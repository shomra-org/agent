import fs from 'node:fs';
import path from 'node:path';
import { CONFIG_DIR } from '../core/config.mjs';

/**
 *  WHICH CALLS AN ORG RULE IS WAITING TO SEE - decided on the machine, cheaply.
 *
 * The local tier decides most calls alone, and it used to decide every
 * `npm install x`, `docker run`, `helm install`, `ollama pull` and every write
 * of a Dockerfile, a compose file, a `package.json` or a workflow alone: none
 * of them is egress, an MCP call or an agent artifact, so none reached the
 * server. Every org rule about packages, images, containers, actions, models,
 * extensions or IaC was dead at runtime unless the machine ran with
 * `SHOMRA_GUARD_ALWAYS_ESCALATE=1` or an agent identity.
 *
 * This is a PRE-classifier. It never decides what a subject IS - the server's
 * extractors do - only which subject TYPES a call could carry, so the hook can
 * ask the server about exactly the calls the org's rules read. Generous where
 * a miss is a dead rule, sniffed where a hit would be every edit of a common
 * file type (`.yaml`, `.py`).
 *
 * ⚠ The type set comes from the server (`subjectTypes` on every guard answer,
 * cached here). UNKNOWN - no answer yet, an old server, an unreadable cache -
 * escalates every subject-bearing call: the failure mode is "checked too
 * often", never "rule dead".
 */

// ── Commands ────────────────────────────────────────────────────────────────

const PKG_INSTALL = [
  /\b(?:npm|pnpm|cnpm)\s+(?:[-\w=]+\s+)*(?:i|install|add|ci|update|up|upgrade)\b/i,
  /\byarn\s+(?:[-\w=]+\s+)*(?:add|install|up|upgrade|dlx|global\s+add)\b|\byarn\s*$/i,
  /\bbun\s+(?:[-\w=]+\s+)*(?:i|install|add|x)\b|\bbunx\b/i,
  /\b(?:npx|pnpx)\s+\S/i,
  /\b(?:pnpm|npm)\s+(?:dlx|exec)\b/i,
  /\b(?:pip3?|pipx|uv\s+pip|(?:python3?|py)\s+-m\s+pip)\s+(?:[-\w=]+\s+)*(?:install|download)\b/i,
  /\buv\s+(?:add|sync|tool\s+install)\b|\buvx\s+\S/i,
  /\bpoetry\s+(?:add|install|update)\b|\bpipenv\s+(?:install|update)\b|\bconda\s+(?:install|create)\b|\bmamba\s+install\b/i,
  /\bgem\s+install\b|\bbundle(?:r)?\s+(?:install|add|update)\b/i,
  /\bcargo\s+(?:install|add)\b|\bgo\s+(?:install|get)\b/i,
  /\bcomposer\s+(?:require|install|update)\b|\bdotnet\s+(?:add\s+package|tool\s+install)\b|\bnuget\s+install\b|\binstall-package\b|\binstall-module\b/i,
  /\b(?:brew|apt|apt-get|yum|dnf|apk|choco|winget|scoop)\s+(?:[-\w=]+\s+)*(?:install|add)\b/i,
  /\bdeno\s+(?:install|add)\b|\bjsr\s+add\b/i,
];
const IMAGE_CMD = /\b(?:docker|podman|nerdctl|finch)\s+(?:(?:--?\S+\s+)*)(?:pull|run|create|build|buildx|compose|stack|service\s+create)\b|\bdocker-compose\b|\bkubectl\s+(?:run|create|apply|set\s+image|debug)\b|\bkind\s+load\b|\bctr\s+(?:image\s+pull|run)\b/i;
const CONTAINER_CMD = /\b(?:docker|podman|nerdctl|finch)\s+(?:(?:--?\S+\s+)*)(?:run|create|compose|service\s+create)\b|\bdocker-compose\b|\bkubectl\s+(?:run|create|apply|debug)\b/i;
const IAC_CMD = /\b(?:terraform|tofu|terragrunt)\s+(?:init|get|apply|plan|import)\b|\bhelm\s+(?:install|upgrade|template|pull|dependency|repo\s+add)\b|\bansible-galaxy\s+(?:install|collection|role)\b|\bpulumi\s+(?:up|preview|package\s+add)\b|\bpre-commit\s+(?:install|autoupdate|run)\b/i;
const MODEL_CMD = /\bollama\s+(?:pull|run|create)\b|\b(?:huggingface-cli|hf)\s+download\b|\bsnapshot_download\b|\bfrom_pretrained\b|\blms?\s+(?:get|load)\b|\bllamafile\b/i;
const EXTENSION_CMD = /--install-extension\b|\bgh\s+extension\s+install\b|\bovsx\s+get\b/i;
const REMOTE_SCRIPT = /\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b[\s\S]{0,400}?\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[\s\S]{0,400}?\|\s*(?:iex|invoke-expression)\b|\b(?:ba|z)?sh\s+<\(\s*(?:curl|wget)\b|\bsource\s+<\(\s*curl\b/i;
const MCP_CMD = /\bmcp\s+add\b|\bclaude\s+mcp\b|@modelcontextprotocol\b|\bmcp[-_]server\b|\bgemini\s+mcp\b|\bcodex\s+mcp\b/i;
const GH_ACTION_CMD = /\bgh\s+workflow\s+(?:run|enable)\b/i;

/**
 * ⚠ THE BINARY IS ITS BASENAME, NOT ITS SPELLING. `npm.cmd install`,
 * `docker.exe run`, `"C:\Program Files\Docker\docker.exe" pull`,
 * `pip3.12 install` and `python3.11 -m pip` stayed LOCAL: every pattern here is
 * keyed on the bare name. Each path-shaped word is reduced to its basename, a
 * Windows launcher suffix is dropped, and a version tail is cut from the
 * interpreters that carry one.
 */
export function normalizeCommand(cmd) {
  // ⚠ A token loop, not one regex: a "path then basename" pattern needs a nested quantifier, which backtracks on attacker text.
  const words = String(cmd ?? '').slice(0, 20_000).split(/(\s+)/);
  for (let k = 0; k < words.length; k++) {
    let w = words[k];
    if (!w || /^\s+$/.test(w)) continue;
    const bare = w.replace(/^["']|["']$/g, '');
    const cut = Math.max(bare.lastIndexOf('/'), bare.lastIndexOf('\\'));
    if (cut >= 0 && /\.(?:exe|cmd|bat)$/i.test(bare)) w = bare.slice(cut + 1);
    w = w.replace(/^([\w-]+)\.(?:exe|cmd|bat)$/i, '$1').replace(/^(pip|pipx|python|py|node|ruby|gem|php|go|dotnet|perl)\d+(?:\.\d+)*$/i, '$1');
    words[k] = w;
  }
  return words.join('');
}

/** The subject types a shell command could carry. */
export function commandSubjectTypes(cmd) {
  const c = normalizeCommand(cmd);
  const out = new Set();
  if (!c.trim()) return out;
  if (PKG_INSTALL.some((re) => re.test(c))) { out.add('package'); out.add('remote-script'); }
  if (IMAGE_CMD.test(c)) out.add('image');
  if (CONTAINER_CMD.test(c)) out.add('container');
  if (IAC_CMD.test(c)) out.add('iac-module');
  if (MODEL_CMD.test(c)) { out.add('model'); out.add('model-file'); }
  if (EXTENSION_CMD.test(c)) out.add('extension');
  if (REMOTE_SCRIPT.test(c)) out.add('remote-script');
  if (MCP_CMD.test(c)) out.add('mcp-server');
  if (GH_ACTION_CMD.test(c)) { out.add('gh-action'); out.add('ci-workflow'); }
  return out;
}

// ── Files a shell command writes ────────────────────────────────────────────

const unquote = (s) => String(s ?? '').replace(/^(["'])([\s\S]*)\1$/, '$2');
const TOKEN = String.raw`("[^"]+"|'[^']+'|[^\s;|&()<>]+)`;
const REDIRECT = new RegExp(String.raw`(?:^|[^<>&\d])>>?\s*` + TOKEN, 'g');
const TEE = new RegExp(String.raw`\btee\s+(?:-\S+\s+)*` + TOKEN, 'g');
const COPY_DEST = new RegExp(String.raw`\b(?:cp|mv|install|copy|move|copy-item|move-item)\s+(?:-\S+\s+)*(?:"[^"]+"|'[^']+'|[^\s;|&()<>]+)\s+(?:-\S+\s+)*` + TOKEN, 'gi');
const SED_INPLACE = new RegExp(String.raw`\bsed\s+(?:-\S+\s+)*-i\S*\s+(?:'[^']*'|"[^"]*"|\S+)\s+` + TOKEN, 'g');
/**
 * ⚠ POWERSHELL WRITES WITHOUT A `>`. `Set-Content`, `Add-Content`, `Out-File`,
 * `New-Item -Value` (and `sc` / `ac`) wrote a Dockerfile or `package.json` that
 * no redirect pattern ever saw. `-Path` / `-FilePath` / `-LiteralPath`, or the
 * first positional argument, is the target; a literal `-Value` is the content.
 */
const PS_WRITE = /\b(set-content|add-content|out-file|new-item|sc|ac)\s([^|;\n]*)/gi;

export function powershellWrite(verb, args) {
  const named = /-(?:path|filepath|literalpath)\s+("[^"]+"|'[^']+'|\S+)/i.exec(args);
  const positional = /^\s*("[^"]+"|'[^']+'|[^\s-]\S*)/.exec(args);
  const target = unquote((named ?? positional)?.[1] ?? '');
  if (!target) return null;
  if (/^new-item$/i.test(verb) && !/-value\b/i.test(args) && !/-itemtype\s+file/i.test(args)) return null;
  const value = /-value\s+(?:'([^']*)'|"([^"]*)")/i.exec(args);
  return { path: target, text: value ? value[1] ?? value[2] : null, append: /^(?:add-content|ac)$/i.test(verb) || /-append\b/i.test(args) };
}

/**
 * The files a shell command WRITES, with their bytes where the command holds
 * them literally. ⚠ Only real write positions - a redirect, `tee`, a copy's
 * destination, `sed -i`, a PowerShell write cmdlet. `python scripts/x.py`
 * named a `.py` path and escalated every script run for model rules: a path an
 * interpreter READS is not a write.
 */
export function shellWriteTargets(cmd) {
  const c = String(cmd ?? '').slice(0, 20_000);
  const out = [];
  const push = (p, text = null) => {
    const t = unquote(p);
    if (t && !t.startsWith('&') && !/^\/dev\//.test(t) && !/^\$null$/i.test(t)) out.push({ path: t, text });
  };
  const here = /<<-?\s*(['"]?)([A-Za-z_][\w-]*)\1[ \t]*\r?\n([\s\S]*?)\r?\n[ \t]*\2\b/.exec(c);
  const echo = /\b(?:echo|printf)\s+(?:-\S+\s+)*(?:'([^']*)'|"([^"]*)")\s*>/.exec(c);
  const inline = here ? here[3] : echo ? echo[1] ?? echo[2] : null;
  for (const m of c.matchAll(REDIRECT)) push(m[1], inline);
  for (const m of c.matchAll(TEE)) push(m[1], inline);
  for (const m of c.matchAll(COPY_DEST)) push(m[1]);
  for (const m of c.matchAll(SED_INPLACE)) push(m[1]);
  for (const m of c.matchAll(PS_WRITE)) {
    const w = powershellWrite(m[1], m[2]);
    if (w) push(w.path, w.text);
  }
  const seen = new Set();
  return out.filter((w) => (seen.has(w.path) ? false : (seen.add(w.path), true))).slice(0, 24);
}

// ── Files ───────────────────────────────────────────────────────────────────

/**
 * ⚠ A PATH CLASS -> EVERY TYPE ITS CONTENT MIGHT DECLARE. Mirrored (as
 * `subjectBearingPath`) by the server's `subject-wiring.ts`, which says a
 * fragment write to one of these is a coverage gap rather than a clean read.
 * A `sniff` row escalates only when the text says it is what a rule reads.
 */
const PATH_TYPES = [
  { re: /(?:^|\/)(?:package\.json|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|requirements[\w.-]*\.(?:txt|in)|constraints\.txt|pyproject\.toml|pipfile(?:\.lock)?|poetry\.lock|uv\.lock|setup\.(?:py|cfg)|go\.(?:mod|sum)|cargo\.(?:toml|lock)|gemfile(?:\.lock)?|composer\.(?:json|lock)|[\w.-]+\.csproj|packages\.config|pom\.xml|build\.gradle(?:\.kts)?|deno\.jsonc?)$/i, types: ['package', 'remote-script'] },
  { re: /(?:^|\/)(?:dockerfile|containerfile)(?:\.[\w.-]+)?$|(?:^|\/)[\w.-]+\.dockerfile$/i, types: ['image', 'container', 'remote-script', 'package'] },
  { re: /(?:^|\/)(?:docker-)?compose(?:[.-][\w-]+)?\.ya?ml$/i, types: ['image', 'container'] },
  { re: /(?:^|\/)\.github\/workflows\/[^/]+\.ya?ml$|(?:^|\/)\.gitlab-ci\.ya?ml$|(?:^|\/)\.github\/actions\/.+\/action\.ya?ml$/i, types: ['ci-workflow', 'gh-action', 'remote-script', 'image', 'container'] },
  { re: /(?:^|\/)\.devcontainer(?:\/[^/]+)?\/devcontainer\.json$|(?:^|\/)\.devcontainer\.json$/i, types: ['dev-environment', 'image', 'container', 'extension'] },
  { re: /\.tf(?:\.json)?$|(?:^|\/)chart\.ya?ml$|(?:^|\/)values(?:[.-][\w-]+)?\.ya?ml$|(?:^|\/)\.pre-commit-config\.ya?ml$|(?:^|\/)requirements\.ya?ml$/i, types: ['iac-module', 'image', 'container'] },
  { re: /(?:^|\/)(?:k8s|kubernetes|manifests?|deploy(?:ment)?s?|helm|charts?|kustomize|argocd|ansible|playbooks?|roles)\/.+\.ya?ml$/i, types: ['image', 'container', 'iac-module'] },
  { re: /\.ya?ml$/i, types: ['image', 'container', 'iac-module', 'ci-workflow', 'gh-action'], sniff: /^\s*(?:services:|apiVersion:|kind:|-?\s*image:|containers:|jobs:|steps:|-?\s*uses:|runs-on:|stages:|-?\s*hosts:|tasks:|roles:|repos:|dependencies:)|^on:/m },
  { re: /(?:^|\/)\.env(?:\.[\w.-]+)?$|(?:^|\/)\.(?:npmrc|pypirc|netrc)$|\.(?:pem|key|tfvars|tfstate)$|(?:^|\/)\.kube\/config$|(?:^|\/)\.aws\/credentials$/i, types: ['secret-file'] },
  { re: /\.(?:safetensors|gguf|ggml|pt|pth|ckpt|onnx|h5|keras|pkl|pickle|joblib|mlmodel|tflite|npz)$/i, types: ['model-file'] },
  { re: /\.(?:py|ipynb)$/i, types: ['model'], sniff: /\b(?:from_pretrained|pipeline\s*\(|SentenceTransformer|torch\.hub|trust_remote_code|hf_hub_download|snapshot_download|load_dataset)\b/ },
  { re: /\.(?:sh|bash|zsh|ps1)$/i, types: ['remote-script'], sniff: /\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b/i },
  { re: /(?:^|\/)\.vscode\/extensions\.json$|\.vsix$/i, types: ['extension'] },
];

const norm = (p) => String(p ?? '').replace(/\\/g, '/');

/**
 * The subject types a write of this path could carry. `text` is what the call
 * writes plus, for an edit, the head of the file already on disk. A `sniff`
 * row whose text does not match is not escalated for.
 * ⚠ Without the sniff every `.yaml` write escalated for image rules and every
 * `.py` edit for model rules - 6 of 16 escalations in a 200-call trace.
 * ⚠ The first NON-sniff row that matches decides (a `compose.yaml` is not also
 * re-read as generic YAML); sniff rows only add.
 */
export function pathSubjectTypes(p, text = null) {
  const out = new Set();
  const n = norm(p);
  if (!n) return out;
  let decided = false;
  for (const row of PATH_TYPES) {
    if (!row.re.test(n)) continue;
    if (row.sniff) {
      if (decided || !(typeof text === 'string' && row.sniff.test(text.slice(0, 256 * 1024)))) continue;
    } else {
      if (decided) continue;
      decided = true;
    }
    for (const t of row.types) out.add(t);
  }
  return out;
}

/** A write whose content the server must see WHOLE to judge a subject rule - see `post_content`. */
export function subjectBearingPath(p) {
  const n = norm(p);
  if (!n) return false;
  if (/\.ya?ml$/i.test(n)) return true;
  return PATH_TYPES.some((row) => !row.sniff && row.re.test(n)) && !/\.(?:safetensors|gguf|ggml|pt|pth|ckpt|onnx|h5|keras|pkl|pickle|joblib|mlmodel|tflite|npz|vsix)$/i.test(n);
}

// ── The call ────────────────────────────────────────────────────────────────

/**
 * The subject types one tool call could carry: its command (shell tools, MCP
 * tools that run a process) and the files it writes, each with its text.
 */
export function preclassifySubjects({ command, writes = [] }) {
  const out = commandSubjectTypes(command);
  for (const w of writes) for (const t of pathSubjectTypes(w.path, w.text)) out.add(t);
  return out;
}

/**
 * ESCALATE WHEN THE ORG HAS A RULE THAT COULD READ THIS CALL.
 *   known set   -> escalate iff the call could carry one of its types
 *   null/absent -> UNKNOWN: escalate every subject-bearing call
 */
export function subjectEscalation(candidates, orgTypes) {
  if (!candidates || !candidates.size) return false;
  if (!Array.isArray(orgTypes)) return true;
  return orgTypes.some((t) => candidates.has(t));
}

// ── The org's type set, learned from the server's answers ───────────────────

export const SUBJECT_TYPES_FILE = path.join(CONFIG_DIR, 'guard-subject-types.json');

/**
 * ⚠ A STALE SET IS TREATED AS UNKNOWN, NOT AS CURRENT, and the EMPTY set goes
 * stale fastest. The pickup window for a new rule is this TTL plus the
 * server's 30 s rule cache. An org that just wrote its FIRST rule is the common
 * case, and it is exactly the one whose cached set is `[]` - so `[]` lives 60 s
 * and a non-empty set 10 min.
 *
 * ⚠ NO SEPARATE RULES-VERSION TOKEN, on purpose: every escalated answer
 * carries the WHOLE current set, and the hook escalates far more than subject
 * calls (every MCP call, artifact read or write, egress, locally flagged call),
 * each of which refreshes it. The residual lag is a machine that escalates
 * nothing at all for the TTL - and then a rule of a NEW type waits at most
 * that long.
 */
export function subjectTypesTtlMs(types = null) {
  const n = Number(process.env.SHOMRA_GUARD_SUBJECT_TTL_MS);
  if (process.env.SHOMRA_GUARD_SUBJECT_TTL_MS && Number.isFinite(n) && n >= 0 && n <= 86_400_000) return n;
  return Array.isArray(types) && types.length === 0 ? 60_000 : 10 * 60_000;
}

export function readSubjectTypes({ file = SUBJECT_TYPES_FILE, url = null, now = Date.now() } = {}) {
  try {
    const row = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (!row || !Array.isArray(row.types) || typeof row.at !== 'number') return null;
    if (url && row.url && row.url !== url) return null;
    if (now - row.at > subjectTypesTtlMs(row.types)) return null;
    return row.types.filter((t) => typeof t === 'string');
  } catch {
    return null;
  }
}

/**
 * Remember the set a server answer carried. ⚠ `null` from the server (it could
 * not read its rules) and an answer with no field (an older server) both CLEAR
 * the cache: the next call escalates rather than trusting a set the server
 * just declined to confirm.
 */
export function rememberSubjectTypes(types, { file = SUBJECT_TYPES_FILE, url = null, now = Date.now() } = {}) {
  try {
    if (!Array.isArray(types)) {
      fs.rmSync(file, { force: true });
      return;
    }
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const tmp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify({ at: now, url, types: types.filter((t) => typeof t === 'string').slice(0, 64) }), { mode: 0o600 });
    fs.renameSync(tmp, file);
  } catch {
    /* an unwritable cache only costs escalations */
  }
}
