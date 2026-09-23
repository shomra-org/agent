import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { MAX_ARTIFACT_BYTES, SKIP_DIRS } from '../artifacts/matchers.mjs';
import { api } from '../core/api-client.mjs';
import { guardTimeoutMs } from '../core/circuit-breaker.mjs';
import { getMachineId, loadConfig, resolveSettings } from '../core/config.mjs';
import { EXIT_USAGE } from '../core/exit-codes.mjs';
import { SEV_COLOR, VERDICT_COLOR, bold, cyan, dim, gray, green, red, yellow } from '../core/terminal.mjs';
import { localGate } from '../detect/guard-signals.mjs';
import { isInstructionPath } from '../detect/signals/instruction-paths.mjs';
import { MACHINE_MEMORY_ROOTS, SERVER_SIDE_MEMORY, classifyMemoryPath, sniffMemoryJsonl } from '../detect/signals/memory-locations.mjs';
import { outOfBandChange, recordLedger, sha256 } from '../guard/memory-write.mjs';

export function memoryLocation(p) {
  return classifyMemoryPath(String(p || '').split(path.sep).join('/'));
}

export function isMemoryPath(p) {
  const rel = String(p || '').split(path.sep).join('/');
  return !!classifyMemoryPath(rel) || isInstructionPath(rel);
}

function walkMemoryFiles(root, maxDepth = 12) {
  const found = [];
  const stack = [{ dir: root, depth: 0 }];
  while (stack.length) {
    const { dir, depth } = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const ent of entries) {
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        if (!SKIP_DIRS.has(ent.name) && depth < maxDepth) stack.push({ dir: full, depth: depth + 1 });
        continue;
      }
      if (!ent.isFile()) continue;
      const rel = path.relative(root, full).split(path.sep).join('/');
      if (isMemoryPath(rel) || isMemoryPath(full) || (/\.(jsonl|ndjson)$/i.test(ent.name) && sniffJsonlFile(full))) found.push({ full, rel });
    }
  }
  return found;
}

function sniffJsonlFile(full) {
  try {
    const fd = fs.openSync(full, 'r');
    const buf = Buffer.alloc(4096);
    const n = fs.readSync(fd, buf, 0, buf.length, 0);
    fs.closeSync(fd);
    return sniffMemoryJsonl(buf.subarray(0, n).toString('utf8'));
  } catch {
    return false;
  }
}

function vscodeUserDirs() {
  const home = os.homedir();
  const bases = process.platform === 'win32'
    ? [process.env.APPDATA || path.join(home, 'AppData', 'Roaming')]
    : process.platform === 'darwin'
      ? [path.join(home, 'Library', 'Application Support')]
      : [process.env.XDG_CONFIG_HOME || path.join(home, '.config')];
  return bases.flatMap((b) => ['Code', 'Code - Insiders', 'Cursor', 'Windsurf', 'VSCodium'].map((app) => path.join(b, app, 'User')));
}

function expandRoot(base, dir) {
  const parts = dir.split('/');
  let paths = [base];
  for (const part of parts) {
    const next = [];
    for (const p of paths) {
      if (part === '*') {
        try {
          for (const ent of fs.readdirSync(p, { withFileTypes: true })) if (ent.isDirectory()) next.push(path.join(p, ent.name));
        } catch {
          continue;
        }
      } else {
        next.push(path.join(p, part));
      }
    }
    paths = next;
  }
  return paths.filter((p) => fs.existsSync(p));
}

export function machineMemoryFiles() {
  const seen = new Set();
  const found = [];
  const home = os.homedir();
  for (const root of MACHINE_MEMORY_ROOTS) {
    const bases = root.base === 'vscode-user' ? vscodeUserDirs() : [home];
    for (const base of bases) {
      for (const dir of expandRoot(base, root.dir)) {
        for (const f of walkMemoryFiles(dir, root.depth)) {
          const key = path.resolve(f.full).toLowerCase();
          if (seen.has(key)) continue;
          seen.add(key);
          const rel = path.relative(home, f.full).split(path.sep).join('/');
          if (!isMemoryPath(rel) && !isMemoryPath(f.full)) continue;
          found.push({ full: f.full, rel: `~/${rel}` });
        }
      }
    }
  }
  return found;
}

export async function reportMemoryWrite(url, apiKey, body) {
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), guardTimeoutMs());
    await fetch(`${url}/memory/ingest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Shomra-Key': apiKey, Connection: 'close' },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });
    clearTimeout(timer);
  } catch {
    return;
  }
}

const NO_STORES_HINT = '(Looked for Claude/Codex/Gemini/Qwen/Windsurf/Goose/Serena memory, memory-bank/, MCP memory.jsonl, mem0/Letta stores, and rules files: CLAUDE.md, AGENTS.md, .cursorrules, copilot-instructions.md, …)';

function resolveMemoryTargets(positional, flags) {
  if (flags.machine) return { target: '~', files: machineMemoryFiles() };
  const argument = positional[0];
  if (!argument) {
    const cwd = process.cwd();
    const local = walkMemoryFiles(cwd).map((f) => ({ ...f, full: f.full }));
    const seen = new Set(local.map((f) => path.resolve(f.full).toLowerCase()));
    const machine = machineMemoryFiles().filter((f) => !seen.has(path.resolve(f.full).toLowerCase()));
    return { target: `${cwd} + this machine's agent memory`, files: [...local, ...machine] };
  }
  const target = path.resolve(String(argument));
  if (!fs.existsSync(target)) {
    console.error(`${red('✗')} Not found: ${argument}`);
    process.exit(EXIT_USAGE);
  }
  return fs.statSync(target).isDirectory()
    ? { target, files: walkMemoryFiles(target) }
    : { target, files: [{ full: target, rel: path.basename(target) }] };
}

function readStore(file) {
  const loc = memoryLocation(file.full) ?? memoryLocation(file.rel);
  if (loc?.format === 'binary') return { content: '', unreadable: `${path.extname(file.full).slice(1) || 'binary'} store`, format: 'binary' };
  try {
    const size = fs.statSync(file.full).size;
    if (size > MAX_ARTIFACT_BYTES) return { content: '', unreadable: `larger than ${Math.round(MAX_ARTIFACT_BYTES / 1_000_000)} MB`, format: loc?.format ?? null };
    return { content: fs.readFileSync(file.full, 'utf8'), unreadable: null, format: loc?.format ?? null };
  } catch (error) {
    return { content: '', unreadable: `could not be opened (${error.code || 'error'})`, format: loc?.format ?? null };
  }
}

function worseVerdict(current, next) {
  if (current === 'FAIL' || next === 'FAIL') return 'FAIL';
  if (current === 'REVIEW' || next === 'REVIEW') return 'REVIEW';
  return 'PASS';
}

function printStore(file, report, note) {
  const verdict = report?.store?.verdict || 'PASS';
  const colour = VERDICT_COLOR[verdict] || gray;
  const poisonScore = report?.store?.poisonScore ?? 0;
  const anomalous = report?.provenance?.anomalous;

  const quarantineNote = report?.quarantined ? ` ${red('QUARANTINED')}` : '';
  const provenanceNote = anomalous ? ` ${red('OUT-OF-BAND WRITE')}` : '';
  const extra = note ? ` ${yellow(note)}` : '';
  console.log(`\n  ${colour('●')} ${bold(path.basename(file.rel))} ${dim(file.rel)} ${colour(verdict)} ${dim(`poison ${poisonScore}/100`)}${quarantineNote}${provenanceNote}${extra}`);

  for (const finding of (report?.analysis?.findings || []).filter((f) => f.severity !== 'INFO')) {
    console.log(`      ${SEV_COLOR[finding.severity](String(finding.severity).padEnd(8))} ${finding.title}`);
  }
  if (anomalous) console.log(`      ${red('provenance:')} ${dim(report.provenance.reason)}`);
}

function summaryLine(worst) {
  if (worst === 'FAIL') return red('✗ Memory poisoning detected - roll back the affected stores.');
  if (worst === 'REVIEW') return yellow('⚠ Review the flagged memory before the agent reloads it.');
  return green('✓ No memory poisoning found.');
}

function writerFor(file, content, flags) {
  if (flags.writer) return { writer: String(flags.writer).toUpperCase(), source: 'shomra memory-scan' };
  if (outOfBandChange(file.full, content)) {
    return { writer: 'UNKNOWN', source: 'changed outside any agent write the Shomra hook observed' };
  }
  return { writer: 'SCAN', source: 'shomra memory-scan' };
}

const LOCAL_VERDICT = { BLOCK: 'FAIL', FLAG: 'REVIEW', ALLOW: 'PASS' };

function printLocalStore(file, verdict, findings, note) {
  const colour = VERDICT_COLOR[verdict] || gray;
  console.log(`\n  ${colour('●')} ${bold(path.basename(file.rel))} ${dim(file.rel)} ${verdict ? colour(verdict) : yellow('NOT READ')}${note ? ` ${yellow(note)}` : ''}`);
  for (const finding of findings.filter((f) => f.severity !== 'INFO')) {
    console.log(`      ${SEV_COLOR[finding.severity](String(finding.severity).padEnd(8))} ${finding.title}${finding.line ? dim(` (line ${finding.line})`) : ''}`);
  }
}

function localMemoryScan(target, files, flags) {
  if (!flags.json) {
    console.log(bold(cyan('\n  Shomra Memory Integrity')) + dim(` - ${files.length} store${files.length > 1 ? 's' : ''} on this machine (${target})`));
  }
  let worst = 'PASS';
  let unread = 0;
  const stores = [];
  for (const file of files) {
    const { content, unreadable } = readStore(file);
    const loc = memoryLocation(file.full) ?? memoryLocation(file.rel);
    if (unreadable) {
      unread++;
      stores.push({ path: file.rel, vendor: loc?.vendor ?? null, unreadable, verdict: null, findings: [] });
      if (!flags.json) printLocalStore(file, null, [], `not read: ${unreadable}`);
      continue;
    }
    const res = localGate(content, { kind: loc ? 'memory' : 'rules', path: file.rel });
    const verdict = LOCAL_VERDICT[res.verdict] ?? 'PASS';
    worst = worseVerdict(worst, verdict);
    stores.push({ path: file.rel, vendor: loc?.vendor ?? null, unreadable: null, verdict, findings: res.findings });
    if (!flags.json) printLocalStore(file, verdict, res.findings);
  }
  if (flags.json) {
    console.log(JSON.stringify({ source: 'local', scanned: stores.length, unread, worst, stores, serverSide: SERVER_SIDE_MEMORY }, null, 2));
  } else {
    if (unread) console.log(`\n  ${yellow('⚠')} ${unread} store${unread > 1 ? 's were' : ' was'} found but not read - reported as not looked inside, never as clean.`);
    console.log(dim(`\n  Not scannable from this machine: ${SERVER_SIDE_MEMORY.map((s) => s.vendor).join(', ')} keep memory server-side.`));
    console.log(`\n  ${summaryLine(worst)}${dim(' Checked on this machine. Enrolled, stores also get a history, out-of-band write detection and rollback.\n')}`);
  }
  if (worst === 'FAIL') process.exitCode = 1;
  else if (worst === 'REVIEW' && flags.strict) process.exitCode = 2;
}

export async function cmdMemoryScan(flags, positional) {
  const cfg = loadConfig();
  const { apiKey, url } = resolveSettings(cfg);

  const { target, files } = resolveMemoryTargets(positional, flags);
  if (!files.length) {
    if (flags.json) console.log(JSON.stringify({ scanned: 0, stores: [] }, null, 2));
    else console.log(dim(`\n  No memory or rules files found under ${target}.\n  ${NO_STORES_HINT}\n`));
    return;
  }
  if (!apiKey || flags.local === true) return localMemoryScan(target, files, flags);

  const machineId = getMachineId(cfg);
  const ingestFields = {
    scope: flags.scope ? String(flags.scope).toLowerCase() : undefined,
    actor: `${os.hostname()}/${os.userInfo().username}`,
    machineId,
    hostname: os.hostname(),
    ...(flags.project ? { projectId: String(flags.project) } : {}),
  };

  if (!flags.json) {
    console.log(bold(cyan('\n  Shomra Memory Integrity')) + dim(` - scanning ${files.length} store${files.length > 1 ? 's' : ''} (${target})`));
  }

  let worst = 'PASS';
  let unread = 0;
  const stores = [];
  for (const file of files) {
    const { content, unreadable, format } = readStore(file);
    if (unreadable) unread++;
    const { writer, source } = writerFor(file, unreadable ? null : content, flags);
    const loc = memoryLocation(file.full) ?? memoryLocation(file.rel);
    const scope = ingestFields.scope ?? (file.rel.startsWith('~/') && !loc?.committed ? 'user' : undefined);

    let report;
    try {
      report = await api(url, apiKey, '/memory/ingest', {
        ...ingestFields,
        ...(scope ? { scope } : {}),
        path: path.resolve(file.full).split(path.sep).join('/'),
        name: path.basename(file.rel),
        content,
        writer,
        source,
        ...(unreadable ? { unreadable } : {}),
        ...(format ? { format } : {}),
      });
    } catch (error) {
      console.error(`  ${red('✗')} ${file.rel} ${red(`ingest error: ${error.message}`)}`);
      continue;
    }
    if (!unreadable) recordLedger(file.full, [sha256(content)]);

    worst = worseVerdict(worst, report?.store?.verdict || 'PASS');
    stores.push({ path: file.rel, vendor: loc?.vendor ?? null, unreadable, ...report });
    if (!flags.json) printStore(file, report, unreadable ? `not read: ${unreadable}` : null);
  }

  if (flags.json) {
    console.log(JSON.stringify({ scanned: stores.length, unread, worst, stores, serverSide: SERVER_SIDE_MEMORY }, null, 2));
  } else {
    if (unread) console.log(`\n  ${yellow('⚠')} ${unread} store${unread > 1 ? 's were' : ' was'} found but not read - reported as not looked inside, never as clean.`);
    console.log(dim(`\n  Not scannable from this machine: ${SERVER_SIDE_MEMORY.map((s) => s.vendor).join(', ')} keep memory server-side.`));
    console.log(`\n  ${summaryLine(worst)}${dim(' Full timeline + rollback in the Shomra dashboard → Memory.\n')}`);
  }

  if (worst === 'FAIL') process.exitCode = 1;
  else if (worst === 'REVIEW' && flags.strict) process.exitCode = 2;
}
