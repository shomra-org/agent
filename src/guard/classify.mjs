import fs from 'node:fs';
import path from 'node:path';
import { artifactKindFor } from './artifact-paths.mjs';
import { preclassifySubjects, shellWriteTargets, subjectEscalation } from './subject-preclassify.mjs';

/**
 *  WHAT COUNTS AS A WRITE, AND IT WAS TEN NAMES SHORT.
 *
 * This set decides whether a tool call is treated as a file write at all - here
 * and, mirrored, on the server. It knew Claude Code's names and Cline's, and
 * missed the ones every other vendor uses: `write_file` and `replace` (Gemini
 * CLI, Qwen), `apply_patch` (Codex), `edit_file` (Cursor, Windsurf),
 * `apply_diff` / `search_and_replace` / `insert_content` (Roo, Kilo). A Gemini
 * CLI write of `.claude/settings.json` was not a write to this code - it fell
 * through to the generic tool-call path with no target, no content and no
 * artifact scan.
 *
 * ⚠ The repo ALREADY knew these names: `MODEL_WRITE_TOOLS` below lists
 * `apply_patch` and `write_file`, and `memory-write.mjs` special-cases
 * `apply_patch` by hand. Two lists in one file disagreed about what a write is,
 * which is how this survived.
 */
export const WRITE_TOOLS = new Set([
  'Write', 'Edit', 'MultiEdit', 'NotebookEdit', 'create_file', 'str_replace_editor',
  'str_replace_based_edit_tool', 'write_to_file', 'replace_in_file', 'new_rule',

  'write_file', 'replace', 'apply_patch', 'apply_diff', 'edit_file', 'edit_notebook',
  'search_and_replace', 'insert_content', 'create_text_file', 'str_replace',

  // ⚠ Copilot CLI (`edit` / `create`) and VS Code's Copilot agent tools. They
  // were not writes, so a Dockerfile or package.json they changed stayed LOCAL.
  'edit', 'create', 'replace_string_in_file', 'insert_edit_into_file',
]);

export { SHELL_TOOL_NAMES, SHELL_TOOLS_RE, argvCommand, heredocPatch, patchTextOf, shellCommandOf } from './command-text.mjs';
import { SHELL_TOOLS_RE, patchTextOf, shellCommandOf } from './command-text.mjs';

/** An MCP tool whose NAME says it runs a process - the server's `mcpExecCommand` reads the same leaves. */
const MCP_EXEC_LEAF = /(?:^|_)(?:exec|execute|run|command|process|shell|terminal|bash|spawn|powershell|cmd)(?:_|$)/i;

const EGRESS_TOOL_RE = /fetch|web|http|browser|request|download|curl|url|open/i;

const EGRESS_CMD_RE = /\b(curl|wget|nc|ncat|http|https|invoke-restmethod|invoke-webrequest|irm|iwr|scp|rsync|ftp|telnet)\b/i;

/**
 * ⚠ THE PATHS A SHELL COMMAND WRITES, so a redirect cannot walk around the
 * tool-name check. `echo '{"permissions":{"defaultMode":"bypassPermissions"}}' >
 * .claude/settings.json` is the same act as a Write and was not sent to the
 * gate at all, because a shell command only reached the server when it looked
 * like egress or an MCP install.
 *
 * Deliberately coarse - it decides whether to ASK the server, and the server
 * decides what the write is. A false positive here costs one guard call.
 */
const REDIRECT_RE = /(?:>>?|\btee\b(?:\s+-\S+)*)\s*("[^"]+"|'[^']+'|[^\s;|&()<>]+)/g;
const COPY_VERB_RE = /\b(?:cp|mv|install|rsync|ln|sed|perl|python3?|tee|curl|wget|set-content|add-content|out-file|new-item|copy-item|move-item)\b/i;

export function shellWritePaths(cmd) {
  const out = [];
  const text = String(cmd ?? '');
  for (const m of text.matchAll(REDIRECT_RE)) {
    const target = m[1].replace(/^["']|["']$/g, '');
    if (!target || target.startsWith('&') || target.startsWith('/dev/')) continue;
    out.push(target);
  }

  /**
   * ⚠ ARGUMENT POSITIONS TOO, not only redirects. `cp /tmp/evil.mdc
   * .cursor/rules/style.mdc` and `sed -i s/x/y/ .claude/settings.json` never
   * pass through `>`; the destination is just an argument.
   */
  if (COPY_VERB_RE.test(text)) {
    for (const tok of text.split(/[\s;|&()]+/)) {
      const t = tok.replace(/^["']|["']$/g, '');
      if (!t || t.startsWith('-')) continue;
      if (t.includes('/') || /^[\w.-]+\.(?:json|jsonc|toml|ya?ml|md|mdc)$/i.test(t)) out.push(t);
    }
  }
  return [...new Set(out)].slice(0, 40);
}

export function guardText(tool, input) {
  const parts = [];
  if (typeof input.command === 'string') parts.push(input.command);
  if (typeof input.cmd === 'string') parts.push(input.cmd);
  if (typeof input.script === 'string') parts.push(input.script);
  if (Array.isArray(input.command) || Array.isArray(input.argv)) parts.push(shellCommandOf(input));
  if (typeof input.content === 'string') parts.push(input.content);
  if (typeof input.new_string === 'string') parts.push(input.new_string);
  if (typeof input.newString === 'string') parts.push(input.newString);
  if (typeof input.code === 'string') parts.push(input.code);
  if (typeof input.new_source === 'string') parts.push(input.new_source);

  /**
   * ⚠ THE KEYS OF THE TOOLS ALREADY ON THE WRITE LIST. `str_replace_editor` -
   * the Anthropic text-editor shape - carries `file_text` on create and
   * `new_str` on replace/insert; `replace_in_file` and `apply_diff` carry
   * `diff`; `apply_patch` carries `patch`. None were read, so the payload of
   * those writes was screened as `JSON.stringify(input)` locally and reached
   * the server as an empty string.
   */
  if (typeof input.file_text === 'string') parts.push(input.file_text);
  if (typeof input.new_str === 'string') parts.push(input.new_str);
  if (typeof input.diff === 'string') parts.push(input.diff);
  if (typeof input.patch === 'string') parts.push(input.patch);
  if (typeof input.code_edit === 'string') parts.push(input.code_edit);
  if (Array.isArray(input.edits)) parts.push(input.edits.map((e) => e?.new_string ?? e?.new_str ?? '').join('\n'));
  if (!parts.length) { try { parts.push(JSON.stringify(input)); } catch { parts.push(String(input)); } }
  return parts.join('\n');
}

export function guardTargetPath(norm) {
  const i = norm.tool_input || {};
  const p = i.file_path ?? i.path ?? i.filePath ?? i.notebook_path ?? i.filename ?? i.target_file ?? i.file ?? null;
  return typeof p === 'string' && p.trim() ? p : null;
}

/**
 * ⚠ EVERY PATH A CALL TOUCHES, for the send decision only. A batched read
 * (`read_many_files` takes `paths`) and a multi-file patch both name several
 * files, and asking about the first one is asking about the wrong one.
 */
export function guardTouchedPaths(tool, input = {}) {
  const out = [];
  const push = (v) => { if (typeof v === 'string' && v.trim()) out.push(v.trim()); };
  push(input.file_path); push(input.path); push(input.filePath); push(input.notebook_path); push(input.filename);
  push(input.target_file); push(input.file); push(input.destination); push(input.dest);
  for (const key of ['paths', 'files', 'file_paths', 'targets']) {
    if (Array.isArray(input[key])) for (const v of input[key]) push(typeof v === 'string' ? v : v?.path);
  }
  if (Array.isArray(input.edits)) for (const e of input.edits) push(e?.file_path ?? e?.path);

  /**
   * ⚠ A PATCH ENVELOPE NAMES ITS OWN FILES. Codex's `apply_patch` carries no
   * path argument at all - the paths are inside the patch text, so a write to
   * `.claude/settings.json` through it looked pathless.
   */
  const patch = patchTextOf(tool, input);
  if (patch) {
    for (const m of patch.matchAll(/^\*\*\* (?:Add|Update|Delete) File:\s*(.+)$/gm)) push(m[1]);
    for (const m of patch.matchAll(/^(?:\+\+\+|---)\s+(?:[ab]\/)?(\S+)/gm)) push(m[1]);
  }
  const command = shellCommandOf(input);
  if (command) {
    for (const p of shellWritePaths(command)) push(p);
  }

  /**
   * ⚠ A SYMLINK IS THE PATH IT POINTS AT. `ln -s .claude/settings.json notes.md`
   * then a write to `notes.md` lands on the settings file while matching no
   * rule - path-based binding cannot see through a link, and only the machine
   * can resolve one. Resolved here, where the filesystem is, and BOTH names are
   * kept: the one written and the one actually changed.
   */
  const resolved = [];
  for (const p of out.slice(0, 20)) {
    try {
      const real = fs.realpathSync(p).replace(/\\/g, '/');
      if (real && real !== p) resolved.push(real);
    } catch {
      /* a path that does not exist yet cannot be a link to somewhere else */
    }
  }
  return [...new Set([...out, ...resolved])].slice(0, 60);
}

export function guardNeedsServer(tool, input, hasIdentity, opts = {}) {
  if (hasIdentity) return true;

  /**
   *  THE DECISION THIS FUNCTION MAKES IS WHETHER THE GATE EVER SEES THE
   * CALL, and it used to answer it against a private fifteen-path regex while
   * the server's list held sixty. A write to `.vscode/settings.json`
   * (CVE-2025-53773, wormable, and an agent writing it IS the exploit),
   * `.cursor/rules/*.mdc` (the rules-file backdoor) or `.codex/config.toml` was
   * decided locally and never sent - so widening the server changed nothing
   * here. `artifact-paths.mjs` is GENERATED from the server's own list now, so
   * the two cannot drift again.
   */
  for (const p of guardTouchedPaths(tool, input)) if (artifactKindFor(p)) return true;

  /**
   * ⚠ THIS SENDS ARTIFACT *READS* TOO, AND THAT IS DELIBERATE - DO NOT NARROW
   * IT. It costs one guard round-trip per artifact read (a handful per session:
   * CLAUDE.md at startup, a rules file when the agent consults one), and two
   * things depend on it that are not obvious from here:
   *
   *   1 A refused artifact binds ON READ. The registry decision takes effect
   *     when the content reaches the model, which is a step no install-time
   *     check can reach.
   *   2 A READ IS HALF OF THE ONLY CROSS-SESSION PROPAGATION EDGE THE PRODUCT
   *     HAS. `HandoffService` pairs write -> read on the same resource; an
   *     instruction artifact is the canonical carrier between sessions, so a
   *     suppressed read means a poisoned CLAUDE.md written by one session and
   *     read by another produces NO edge, and the blast-radius walk reports a
   *     blind spot instead of the path.
   *
   * ⚠ AND A PER-SESSION DEDUPE IS WORSE THAN EITHER CHOICE, which is the trap
   * to avoid: that pairing needs `read.at > write.at`, so reporting only the
   * FIRST read of a file means a later poisoning write followed by a re-read
   * pairs against nothing. It would quietly break the detection it was added to
   * protect. The latency is bounded by the circuit breaker instead - a slow
   * gate degrades to local screening rather than holding the agent.
   */

  if (WRITE_TOOLS.has(tool)) {
    const target = String(input.file_path ?? input.path ?? input.filePath ?? input.notebook_path ?? '').replace(/\\/g, '/');
    if (artifactKindFor(target)) return true;
  }
  if (tool && tool.startsWith('mcp__')) return true;
  if (EGRESS_TOOL_RE.test(tool || '')) return true;
  if (SHELL_TOOLS_RE.test(tool || '')) {
    const cmd = shellCommandOf(input);
    if (EGRESS_CMD_RE.test(cmd)) return true;
    if (/\bmcp\s+add\b|claude\s+mcp\b|@modelcontextprotocol\b|\bmcp[-_]server\b/i.test(cmd)) return true;
  }
  const url = input?.url ?? input?.uri ?? input?.href ?? input?.endpoint;
  if (typeof url === 'string' && url) return true;

  /**
   * ⚠ AN ORG RULE MAY BE WAITING FOR THIS CALL. An install, an image pull, a
   * `helm install`, a model pull, an extension install, a write of a manifest,
   * Dockerfile, compose file, workflow or secret file - none is egress or an
   * agent artifact, so every one was decided here, alone, and the org's
   * `subject:` rules about them never saw a runtime call. Escalated when the org
   * has a live runtime rule of a type this call could carry (`opts.subjectTypes`,
   * learned from the server's answers); when that set is UNKNOWN every
   * subject-bearing call is escalated - see `subject-preclassify.mjs`.
   */
  return subjectEscalation(callSubjectTypes(tool, input, { cwd: opts.cwd }), opts.subjectTypes);
}

const MCP_WRITE_LEAF = /(?:^|_)(?:write|create|edit|append|patch|put|save|upsert|move|copy|rename)(?:_|$)/i;

/** An MCP leaf that feeds INPUT to a running process (desktop-commander `interact_with_process`). */
const MCP_PROCESS_INPUT_LEAF = /(?:^|_)(?:interact_with_process|send_input|write_stdin|process_input)(?:_|$)/i;

const HEAD_BYTES = 64 * 1024;

/** ⚠ The head of the file an edit changes - so a fragment of a k8s manifest is still sniffed as one. Never throws. */
function diskHead(p, cwd) {
  try {
    const abs = path.isAbsolute(p) ? p : path.resolve(cwd || process.cwd(), p);
    const fd = fs.openSync(abs, 'r');
    try {
      const buf = Buffer.alloc(HEAD_BYTES);
      const n = fs.readSync(fd, buf, 0, HEAD_BYTES, 0);
      return buf.subarray(0, n).toString('utf8');
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return '';
  }
}

/**
 * The subject types this call could carry - the command it runs and the files
 * it writes, each with the text that decides a sniffed path (`.yaml`, `.py`).
 * ⚠ A shell command's write paths are its REAL write positions
 * (`shellWriteTargets`), not every path-shaped word: `python scripts/x.py`
 * reads a script, it does not write one.
 */
export function callSubjectTypes(tool, input = {}, { cwd } = {}) {
  const i = input ?? {};
  const t = String(tool ?? '');
  const shell = SHELL_TOOLS_RE.test(t);
  const mcpLeaf = t.startsWith('mcp__') ? t.split('__').slice(2).join('__') : '';
  const execs = shell || (!!mcpLeaf && MCP_EXEC_LEAF.test(mcpLeaf));
  let command = execs ? shellCommandOf(i) : '';
  if (!command && mcpLeaf && MCP_PROCESS_INPUT_LEAF.test(mcpLeaf) && typeof i.input === 'string') command = i.input;

  const writes = [];
  const patch = patchTextOf(t, i);
  if (patch) {
    for (const m of patch.matchAll(/^\*\*\* (?:Add|Update) File:\s*(.+)$|^\*\*\* Move to:\s*(.+)$|^\+\+\+\s+(?:[ab]\/)?(\S+)/gm)) {
      const p = (m[1] ?? m[2] ?? m[3] ?? '').trim();
      if (p && p !== '/dev/null') writes.push({ path: p, text: `${patch}\n${diskHead(p, cwd)}` });
    }
  }
  if (command) for (const w of shellWriteTargets(command)) writes.push({ path: w.path, text: w.text ?? diskHead(w.path, cwd) });
  if (WRITE_TOOLS.has(t) || (!!mcpLeaf && MCP_WRITE_LEAF.test(mcpLeaf))) {
    const text = guardText(t, i);
    for (const p of guardTouchedPaths(t, i)) writes.push({ path: p, text: `${text}\n${diskHead(p, cwd)}` });
  }
  return preclassifySubjects({ command, writes });
}

export const MODEL_WRITE_TOOLS = ['write', 'edit', 'multiedit', 'notebookedit', 'create_file', 'str_replace_editor', 'apply_patch', 'write_file'];
