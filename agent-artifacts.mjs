/**
 * INSTALLED AGENT ARTIFACTS — the prompt-as-code an agent on this machine loads
 * and treats as trusted instructions.
 *
 * `discovery.mjs` answers "what AI tooling is on this laptop" and `agent-posture.mjs`
 * answers "what is it allowed to do without asking". Neither answers the third
 * question, which is the one the 2026 attack surface actually lives in: WHAT IS IT
 * TOLD TO DO. A skill, a slash command, a subagent definition and a lifecycle hook
 * are executable instructions the agent obeys without a human in the loop, and the
 * dangerous ones are USER-SCOPE — `~/.claude/skills/…` governs every repository on
 * the machine and appears in none of them. A repo scanner structurally cannot see
 * it. That gap is this module.
 *
 * The platform already knows how to judge these: the same detector + analyzer the
 * workspace scan uses classifies them by path and grades them. So this module is
 * deliberately DUMB — it locates files and reads bytes. It makes no security
 * judgement of its own, because a second, weaker grader running on the endpoint
 * would drift from the one that governs everything else and quietly become the
 * authority nobody audits.
 *
 * ── What leaves the machine ──────────────────────────────────────────────────
 *
 * The INSTRUCTION DOCUMENT, and nothing else on its shelf.
 *
 * A SKILL.md, a slash command and a subagent definition ARE the security object —
 * shipping them is the same trade `discoverRulesFiles` already makes for CLAUDE.md
 * and .cursorrules, and there is nothing left to analyse if the body stays home.
 *
 * Hooks are the exception, and it is the one that matters. A hook lives INSIDE
 * `settings.json`, next to the API keys, local paths and personal preferences that
 * `agent-posture.mjs` refuses on principle to transmit. So a hook is extracted
 * into a canonical `{ "hooks": … }` document and only that document is sent; the
 * settings file it came out of never leaves. The backend's hook detector reads the
 * `hooks` key and nothing else, so this loses no fidelity whatsoever — it is
 * strictly a decision not to ship the rest of the file because it was convenient.
 *
 * ⚠ COROLLARY, and it is easy to undo by accident: no code path here may widen a
 * hook read to the whole document "so the analyzer has more context". The analyzer
 * does not want it, and the first version that ships it has turned a posture agent
 * into the exfiltration channel it was sold to prevent.
 *
 * ── Bundled files ───────────────────────────────────────────────────────────
 *
 * A skill is a directory, not a file. Its `SKILL.md` says `bash scripts/setup.sh`
 * and the SCRIPT is the program — grading the markdown alone reads the cover of a
 * book. The backend's detector adopts a skill's directory siblings onto it, so the
 * bundled files are shipped alongside, capped and text-only. Binary payloads are
 * REPORTED BY PATH AND NOT BY CONTENT: their presence in a skill is a fact worth
 * knowing, and a base64'd .so is not a fact worth uploading.
 *
 * ── Where this deliberately stops ───────────────────────────────────────────
 *
 * Rules / instruction files (CLAUDE.md, .cursorrules, AGENTS.md) are NOT collected
 * here. `discoverRulesFiles` already reports them as AI_RULES assets and the
 * backend routes them into their own governed store; a file arriving down both
 * paths would hold two governance objects that disagree about its baseline. One
 * surface, one owner.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { clampArtifact } from './wire-limits.mjs';

const HOME = os.homedir();

/** Registrable kinds. Mirrors the backend's REGISTRY_KINDS subset we can locate. */
export const ARTIFACT_KINDS = ['skill', 'command', 'subagent', 'hook'];

// ── Caps ─────────────────────────────────────────────────────────
// Every one of these is a REPORT bound, not a correctness knob. A developer
// machine is not a scan target and this runs on a check-in interval: it may cost
// a directory walk, never a disk read. When a cap bites we say so (see `capped`)
// rather than silently returning a short list that reads as "that's all there is".

const MAX_DEPTH = 6; // from a vendor root — reaches plugins/<pack>/skills/<x>/
const MAX_DIRS = 4_000; // directories visited across all roots
const MAX_ARTIFACTS = 400; // artifacts in one report
const MAX_FILE_BYTES = 64_000; // per document
const MAX_BUNDLED = 20; // files adopted onto one skill
const MAX_TOTAL_BYTES = 4_000_000; // total content in one report

const IGNORE_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'out', 'coverage', '__pycache__',
  '.venv', 'venv', 'site-packages', '.next', '.turbo', 'target',
  // Agent-owned caches and transcripts. Large, churning, and not instructions:
  // `projects/` alone is every session this machine has ever run.
  'projects', 'todos', 'statsig', 'shell-snapshots', 'history', 'logs', 'cache',
]);

/** Text we will ship. Anything else in a skill dir is reported by path only. */
const TEXT_EXTS = new Set([
  'md', 'mdc', 'markdown', 'txt', 'toml', 'json', 'jsonc', 'yaml', 'yml',
  'sh', 'bash', 'zsh', 'ps1', 'bat', 'cmd', 'py', 'js', 'mjs', 'cjs', 'ts',
  'rb', 'pl', 'lua', 'sql', 'env', 'cfg', 'ini', 'conf',
]);

const extOf = (p) => {
  const b = path.basename(p);
  const i = b.lastIndexOf('.');
  return i > 0 ? b.slice(i + 1).toLowerCase() : '';
};

/**
 * Vendor roots that own agent artifacts, per scope.
 *
 * ⚠ Best-effort and deliberately over-broad: a path a vendor never used costs one
 * `readdir` that fails, while a path we omitted is a governed artifact nobody can
 * see. Every root here is vendor-namespaced, so an extra entry can only
 * under-report — it can never claim a file that isn't an agent's.
 */
export function artifactRoots(cwd = process.cwd()) {
  return [
    { vendor: 'claude-code', scope: 'user', dir: path.join(HOME, '.claude') },
    { vendor: 'claude-code', scope: 'project', dir: path.join(cwd, '.claude') },
    { vendor: 'cursor', scope: 'user', dir: path.join(HOME, '.cursor') },
    { vendor: 'cursor', scope: 'project', dir: path.join(cwd, '.cursor') },
    { vendor: 'codex', scope: 'user', dir: path.join(HOME, '.codex') },
    { vendor: 'codex', scope: 'project', dir: path.join(cwd, '.codex') },
    { vendor: 'gemini', scope: 'user', dir: path.join(HOME, '.gemini') },
    { vendor: 'gemini', scope: 'project', dir: path.join(cwd, '.gemini') },
    { vendor: 'windsurf', scope: 'project', dir: path.join(cwd, '.windsurf') },
    { vendor: 'opencode', scope: 'user', dir: path.join(HOME, '.opencode') },
    { vendor: 'opencode', scope: 'project', dir: path.join(cwd, '.opencode') },
    // Copilot keeps prompts and chat modes in the repo's `.github`. Only those two
    // subtrees are considered (see classify) — `.github` at large is CI, issue
    // templates and CODEOWNERS, none of which an agent loads as instructions.
    { vendor: 'copilot', scope: 'project', dir: path.join(cwd, '.github') },
  ];
}

/** Settings documents that may carry a `hooks` block. Read for hooks ONLY. */
const SETTINGS_BASENAMES = new Set([
  'settings.json', 'settings.local.json', 'hooks.json', 'config.toml',
]);

// ── Activation: available is not installed ───────────────────────
//
// A cloned plugin MARKETPLACE is a catalogue. On a machine with three of them
// checked out and no plugin actually enabled, a naive sweep finds ~380 skills,
// commands and subagents and reports every one as installed. That is wrong twice
// over: it overstates the machine's exposure by two orders of magnitude, and it
// puts hundreds of rows per machine into a registry whose value is that a row
// there means something.
//
// So activation is resolved from the plugin manifest, and the two states are
// reported differently in KIND, not just in degree:
//
//   ACTIVE     the agent loads it. Reported as an artifact, graded, governed.
//   AVAILABLE  sitting in a checked-out catalogue, one command from active.
//              Reported as a COUNT on its marketplace — one fact, not N facts.
//
// ⚠ UNREADABLE MANIFEST ⇒ REPORT EVERYTHING, marked `unknown`. This is the
// opposite of the usual rule, and deliberately: the failure direction here is
// NOISE, not reassurance. Hiding a catalogue because we could not parse a JSON
// file would make an unparseable manifest the cheapest way to conceal an
// installed plugin, and that is a hole. An over-reported inactive skill is a row
// somebody dismisses; an under-reported active one is the incident.

const PLUGIN_PATH_RE = /(^|\/)plugins\/marketplaces\/([^/]+)\//;

/**
 * Staging, vendored and bundled trees — catalogues by construction, whatever the
 * vendor calls them. Codex stages `bundled-marketplaces`, `marketplaces` and
 * `plugins` under `.tmp/`, and vendors a curated skill set under
 * `vendor_imports/`; on this machine that was 372 skills the agent does not load,
 * against 4 it does.
 *
 * ⚠ These are COUNTED, not ignored. `IGNORE_DIRS` makes a tree invisible, which is
 * the right call for a transcript directory and the wrong one here: a checked-out
 * catalogue is a real supply-chain fact — it is one command from being active, and
 * its contents were fetched from somewhere. Counting it says so without claiming
 * 372 governed artifacts that do not exist.
 */
const CATALOGUE_DIR_RE = /(^|\/)(\.tmp|tmp|temp|vendor_imports|bundled-marketplaces|backups?)\//i;

/**
 * Which marketplaces have at least one INSTALLED plugin.
 *
 * Returns null when the manifest cannot be read or parsed — which callers must
 * treat as "cannot rule anything out", never as "nothing is installed".
 */
export function installedMarketplaces(root) {
  // ⚠ TWO SOURCES, UNIONED. `plugins/installed_plugins.json` records what was
  // installed; `settings.json`'s `enabledPlugins` records what is switched on, and
  // the settings file may carry an entry the manifest does not. Reading one and
  // calling it the answer means a plugin enabled through the other channel reports
  // as an inert catalogue — the under-report this whole gate exists to avoid. If
  // EITHER is present and unparseable the answer is null (cannot rule out).
  const out = new Set();

  const manifest = readJsonAt(path.join(root, 'plugins', 'installed_plugins.json'));
  if (manifest === undefined) return null; // present, unparseable
  if (manifest !== null) {
    const plugins = manifest?.plugins;
    if (plugins && typeof plugins === 'object') {
      for (const [key, value] of Object.entries(plugins)) {
        addPluginKey(out, key);
        const named = value && typeof value === 'object' ? (value.marketplace ?? value.source) : null;
        if (typeof named === 'string') out.add(named);
      }
    }
  }

  for (const f of ['settings.json', 'settings.local.json']) {
    const doc = readJsonAt(path.join(root, f));
    if (doc === undefined) return null;
    if (doc === null) continue;
    const enabled = doc?.enabledPlugins;
    if (enabled && typeof enabled === 'object') {
      for (const key of Object.keys(enabled)) addPluginKey(out, key);
    }
  }

  // An empty set means BOTH sources were read and neither named a marketplace —
  // "nothing is active", which is a read. It is not the same value as `null`, and
  // the two must never be merged: null is "we could not tell".
  return out;
}

/** `plugin@marketplace` → the marketplace; a bare key is taken as one. */
function addPluginKey(set, key) {
  const at = String(key).indexOf('@');
  set.add(at > -1 ? String(key).slice(at + 1) : String(key));
}

/**
 * `null` = absent, `undefined` = present and unparseable, object = parsed.
 * Three outcomes because the caller must distinguish "no plugin system" from
 * "a file we could not read", and collapsing them is how the second becomes
 * silently reassuring.
 */
function readJsonAt(file) {
  let raw;
  try {
    raw = fs.readFileSync(file, 'utf8');
  } catch {
    return null;
  }
  try {
    return JSON.parse(stripJsonComments(raw));
  } catch {
    return undefined;
  }
}

function readText(file, cap = MAX_FILE_BYTES) {
  try {
    const st = fs.statSync(file);
    if (!st.isFile()) return null;
    const fd = fs.openSync(file, 'r');
    try {
      const len = Math.min(st.size, cap);
      const buf = Buffer.alloc(len);
      fs.readSync(fd, buf, 0, len, 0);
      // A NUL in the first block means binary, whatever the extension claimed.
      if (buf.includes(0)) return null;
      return { text: buf.toString('utf8'), truncated: st.size > cap, bytes: st.size };
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return null;
  }
}

/**
 * Classify a file under a vendor root into a registrable kind, by CONVENTION —
 * the same convention the backend's detector uses, so the two agree on what a
 * thing is before either grades it.
 *
 * Returns null for everything else, which is most of a vendor directory.
 */
function classify(rel, vendor) {
  const lower = rel.toLowerCase().replace(/\\/g, '/');
  const base = path.basename(lower);
  const ext = extOf(lower);

  if (base === 'skill.md') return 'skill';
  if (SETTINGS_BASENAMES.has(base)) return 'hook'; // only if a hooks block is present
  if (/(^|\/)(sub)?agents?\//.test(lower) && ext === 'md') return 'subagent';
  if (/(^|\/)(commands?|prompts?|workflows?)\//.test(lower) && (ext === 'md' || ext === 'toml')) {
    // Copilot's two instruction subtrees; the rest of `.github` is not an agent
    // surface and must not be swept in.
    if (vendor === 'copilot' && !/(^|\/)(prompts|chatmodes)\//.test(lower)) return null;
    return 'command';
  }
  if (vendor === 'copilot' && /(^|\/)chatmodes\//.test(lower) && ext === 'md') return 'subagent';
  return null;
}

/** One bounded breadth-first walk of a vendor root. Returns relative file paths. */
function walkRoot(dir, budget) {
  const out = [];
  const seen = new Set();
  const queue = [{ d: dir, depth: 0 }];
  while (queue.length && budget.dirs > 0) {
    const { d, depth } = queue.shift();
    let real;
    try {
      real = fs.realpathSync(d);
    } catch {
      continue;
    }
    if (seen.has(real)) continue; // symlink loops, shared roots
    seen.add(real);
    budget.dirs--;
    let entries;
    try {
      entries = fs.readdirSync(d, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) {
        if (depth < MAX_DEPTH && !IGNORE_DIRS.has(e.name)) queue.push({ d: full, depth: depth + 1 });
      } else if (e.isFile()) {
        out.push(full);
      }
    }
  }
  return out;
}

/**
 * The hooks block, and only the hooks block, as its own document.
 *
 * ⚠ See the header. The returned string is what the backend receives INSTEAD OF
 * the settings file, not in addition to it. `hooks` absent → null, and the file is
 * not reported at all: a settings.json with no hooks is a preferences file, and
 * this module has no business knowing it exists.
 */
export function canonicalHooks(text) {
  let doc;
  try {
    doc = JSON.parse(stripJsonComments(text));
  } catch {
    return null;
  }
  if (!doc || typeof doc !== 'object') return null;
  const hooks = doc.hooks;
  if (!hooks || typeof hooks !== 'object' || !Object.keys(hooks).length) return null;
  return JSON.stringify({ hooks }, null, 2);
}

/** VS Code / Cursor settings are JSONC — tolerate comments before parsing. */
function stripJsonComments(s) {
  return String(s)
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/.*$/gm, '$1');
}

/** Frontmatter `name:` if the document declares one — the artifact's real name. */
function declaredName(text) {
  const m = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
  if (!m) return null;
  const n = /^name:\s*(.+)$/m.exec(m[1]);
  return n ? n[1].trim().replace(/^["']|["']$/g, '').slice(0, 120) || null : null;
}

/**
 * Discover every installed agent artifact reachable from this machine's vendor
 * roots.
 *
 * Returns `{ artifacts, capped }`. `capped` is not decoration — a caller that
 * renders a count without it is publishing a denominator it does not have, which
 * is the failure `posture-rollup.ts` exists to refuse at the fleet level.
 */
export function discoverAgentArtifacts(cwd = process.cwd(), roots = null) {
  const sites = roots || artifactRoots(cwd);
  const budget = { dirs: MAX_DIRS, bytes: MAX_TOTAL_BYTES };
  const capped = [];
  const artifacts = [];
  const project = path.basename(path.resolve(cwd)) || null;
  /** Files already shipped as a skill's bundle — never emitted twice. */
  const consumed = new Set();
  /** Skill directories, so bundling happens after every root is walked. */
  const skills = [];
  /** Every file each root's single walk turned up — reused for bundling. */
  const walked = [];

  // Marketplace catalogues: what's checked out, and how much of it is inert.
  /** marketplace → count of artifacts NOT reported because no plugin is installed. */
  const availableBy = new Map();

  const seenRoot = new Set();
  for (const site of sites) {
    let realRoot;
    try {
      realRoot = fs.realpathSync(site.dir);
    } catch {
      continue; // vendor not installed here — the common case, and not an error
    }
    // `~/.claude` and `<cwd>/.claude` are the same directory when the CLI runs
    // from HOME. Walking both would report every user-scope artifact twice, once
    // per scope, and the duplicate would look like fleet drift.
    if (seenRoot.has(realRoot)) continue;
    seenRoot.add(realRoot);

    // ⚠ ONE walk per root. The bundling pass below filters THESE results by
    // directory prefix rather than walking again: a second walk would re-charge
    // the directory budget for ground already covered, and on a machine with many
    // skills that budget is what stops a check-in becoming a disk crawl.
    const files = walkRoot(site.dir, budget);
    walked.push({ site, files });
    // Resolved per root, once. `null` = a source was present but unreadable.
    const installed = installedMarketplaces(site.dir);
    for (const full of files) {
      if (artifacts.length >= MAX_ARTIFACTS) {
        capped.push({ reason: 'artifact-cap', path: full });
        break;
      }
      const rel = path.relative(path.dirname(site.dir), full).replace(/\\/g, '/');
      const kind = classify(rel, site.vendor);
      if (!kind) continue;

      // ── Activation gate ──
      // A staging / vendored tree is a catalogue outright — no manifest can make
      // `.tmp/` the thing the agent loads. Checked before the plugin gate so a
      // marketplace STAGED under `.tmp/` counts once, as the catalogue it is.
      const cat = CATALOGUE_DIR_RE.exec(rel);
      if (cat) {
        const label = `${site.vendor}:${cat[2].toLowerCase()}`;
        availableBy.set(label, (availableBy.get(label) ?? 0) + 1);
        continue;
      }

      const mp = PLUGIN_PATH_RE.exec(rel)?.[2] ?? null;
      let activation = 'active';
      if (mp) {
        if (installed === null) {
          activation = 'unknown'; // reported, and said to be uncertain
        } else if (!installed.has(mp)) {
          // Counted on its marketplace and NOT emitted as a row. The count is the
          // honest unit for a catalogue: an operator wants "3 marketplaces, 380
          // skills available, none enabled", not 380 governance objects.
          availableBy.set(mp, (availableBy.get(mp) ?? 0) + 1);
          continue;
        }
      }

      const read = readText(full);
      if (!read) continue;
      if (read.bytes > budget.bytes) {
        capped.push({ reason: 'byte-budget', path: rel });
        continue;
      }

      let content = read.text;
      if (kind === 'hook') {
        // ⚠ The canonical document REPLACES the file. See the header.
        content = canonicalHooks(read.text);
        if (!content) continue; // no hooks block → not an artifact, not reported
      }

      budget.bytes -= Buffer.byteLength(content);
      const name =
        declaredName(content) ||
        (kind === 'skill'
          ? path.basename(path.dirname(full))
          : kind === 'hook'
            ? `${path.basename(full)} · hooks`
            : path.basename(full).replace(/\.(md|toml)$/i, ''));

      const artifact = {
        kind,
        name: String(name).slice(0, 200),
        // Scope-relative, forward-slashed. The absolute path is not sent: it adds
        // the developer's home directory to every row and is not part of the
        // artifact's identity — the backend keys these by machine already.
        path: rel,
        scope: site.scope,
        vendor: site.vendor,
        content,
        files: [],
        metadata: {
          bytes: read.bytes,
          truncated: read.truncated,
          project: site.scope === 'project' ? project : null,
          activation,
          marketplace: mp,
        },
      };
      consumed.add(full);
      artifacts.push(artifact);
      if (kind === 'skill') skills.push({ artifact, dir: path.dirname(full), site });
    }
  }

  // ── Bundled files ──
  // A skill's directory is its program. Adopted after the walk so a script that
  // also classifies as something else (a `commands/` markdown inside a skill pack)
  // stays with the skill that ships it, matching the backend detector's order.
  for (const { artifact, dir, site } of skills) {
    const prefix = dir.endsWith(path.sep) ? dir : dir + path.sep;
    const entries = (walked.find((w) => w.site === site)?.files ?? []).filter((f) => f.startsWith(prefix));
    for (const full of entries) {
      if (consumed.has(full)) continue;
      if (artifact.files.length >= MAX_BUNDLED) {
        capped.push({ reason: 'bundle-cap', path: artifact.path });
        break;
      }
      const rel = path.relative(path.dirname(site.dir), full).replace(/\\/g, '/');
      const ext = extOf(full);
      if (!TEXT_EXTS.has(ext)) {
        // Present and unread. A binary in a skill bundle is a fact the platform
        // should hold; its bytes are not something a posture agent should upload.
        artifact.files.push({ path: rel, content: null, binary: true });
        consumed.add(full);
        continue;
      }
      const read = readText(full);
      if (!read) {
        artifact.files.push({ path: rel, content: null, binary: true });
        consumed.add(full);
        continue;
      }
      if (read.bytes > budget.bytes) {
        capped.push({ reason: 'byte-budget', path: rel });
        continue;
      }
      budget.bytes -= Buffer.byteLength(read.text);
      artifact.files.push({ path: rel, content: read.text, binary: false });
      consumed.add(full);
    }
    artifact.metadata.bundledCount = artifact.files.length;
  }

  if (budget.dirs <= 0) capped.push({ reason: 'walk-budget', path: null });

  // One row per checked-out catalogue. Not artifacts, and deliberately a separate
  // field rather than artifacts with a flag: anything on `artifacts` is registered
  // and governed, and a catalogue is neither.
  const available = [...availableBy.entries()]
    .map(([marketplace, count]) => ({ marketplace, count, installed: false }))
    .sort((a, b) => b.count - a.count);

  // ⚠ Clamped on the way out, same reason as `discoverAll`: the report is
  // validated all-or-nothing, so one over-long path costs the machine every
  // artifact AND every asset in the same check-in. See wire-limits.mjs.
  return { artifacts: artifacts.map(clampArtifact), capped, available };
}

/** Count by kind — what the CLI prints and the report summarises. */
export function rollupArtifacts(artifacts) {
  const by = {};
  for (const a of artifacts) by[a.kind] = (by[a.kind] ?? 0) + 1;
  return by;
}
