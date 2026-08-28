import fs from 'node:fs';
import path from 'node:path';
import { MAX_ARTIFACT_BYTES, SKIP_DIRS } from '../artifacts/matchers.mjs';
import { api } from '../core/api-client.mjs';
import { loadConfig, resolveSettings } from '../core/config.mjs';
import { EXIT_USAGE, exitNotConfigured } from '../core/exit-codes.mjs';
import { SEV_COLOR, bold, cyan, dim, green, red, yellow } from '../core/terminal.mjs';
import { CAP_LABEL, analyzeDesign, designChecklist } from '../detect/design.mjs';

export async function cmdDesign(flags, positional) {
  const target = positional[0] || flags.path;
  if (!target) {
    console.error(red('✗') + ' Usage: ' + bold('shomra design <file|dir|->') + dim('  (use - to read a ticket/RFC on stdin)'));
    console.error(dim('  e.g. ') + 'gh issue view 42 --json body -q .body | shomra design -');
    process.exit(EXIT_USAGE);
  }

  const docs = [];
  if (target === '-' || flags.stdin) {
    docs.push({ name: flags.name ? String(flags.name) : 'stdin', text: fs.readFileSync(0, 'utf8') });
  } else {
    const abs = path.resolve(String(target));
    if (!fs.existsSync(abs)) {
      console.error(red('✗') + ` Not found: ${target}`);
      process.exit(EXIT_USAGE);
    }
    if (fs.statSync(abs).isDirectory()) {
      for (const f of walkDesignDocs(abs)) {
        try { if (fs.statSync(f.full).size <= MAX_ARTIFACT_BYTES) docs.push({ name: f.rel, text: fs.readFileSync(f.full, 'utf8') }); } catch {  }
      }
      if (!docs.length) {
        console.error(red('✗') + ` No design documents (.md / .txt / .rst) found under ${target}.`);
        process.exit(EXIT_USAGE);
      }
    } else {
      docs.push({ name: path.relative(process.cwd(), abs).split(path.sep).join('/'), text: fs.readFileSync(abs, 'utf8') });
    }
  }

  const results = docs.map((d) => analyzeDesign(d.text, { name: d.name }));
  const open = results.filter((r) => r.verdict === 'OPEN_PATH');
  const critical = results.filter((r) => r.worst === 'CRITICAL');

  if (flags.json) {
    console.log(JSON.stringify({ documents: results.length, openPaths: open.length, critical: critical.length, results }, null, 2));
  } else if (flags.checklist) {

    console.log(results.map(designChecklist).join('\n---\n\n'));
  } else {
    for (const r of results) printDesign(r);
    if (results.length > 1) {
      console.log(
        `  ${open.length ? red(`✗ ${open.length} of ${results.length} documents describe a closed attack path`) : yellow(`• no closed path described in ${results.length} documents`)}\n`,
      );
    }
  }

  if (flags.save) await saveDesign(results, flags);

  if (critical.length) process.exitCode = 1;
  else if (open.length && flags.strict) process.exitCode = 2;
}

async function saveDesign(results, flags) {
  const { apiKey, url } = resolveSettings(loadConfig());
  const subject = String(flags.subject ?? '').trim();
  const m = /^(AGENT|PROJECT|DESIGN):(.+)$/i.exec(subject);
  if (!m) {
    console.error(red('✗') + ' --save needs ' + bold('--subject KIND:id') + dim('  (AGENT | PROJECT | DESIGN)'));
    console.error(dim('  e.g. ') + 'shomra design docs/rfc.md --save --subject DESIGN:inbox-agent');
    process.exit(EXIT_USAGE);
  }
  if (results.length !== 1) {
    console.error(red('✗') + ` --save takes one document; ${results.length} were modelled.`);
    console.error(dim('  Save each against its own subject.'));
    process.exit(EXIT_USAGE);
  }
  if (!apiKey || !url) exitNotConfigured();

  const [, kind, id] = m;
  const r = results[0];
  process.stdout.write(dim('  Saving to the platform… '));
  try {
    const res = await api(url, apiKey, '/threat-models/agent-author', {
      subjectKind: kind.toUpperCase(),
      subjectId: id,
      title: flags.title ? String(flags.title) : r.name,
      analysis: r,
      note: flags.note ? String(flags.note) : `Modelled from ${r.name}.`,
      actor: flags.actor ? String(flags.actor) : undefined,
    });
    const v = res?.version;
    const c = res?.coverage;
    console.log(green('saved') + dim(` - v${v?.seq ?? '?'}, ${v?.reviewState ?? 'IN_REVIEW'}`));

    console.log(dim('  It is not approved yet - a threat model must be reviewed by someone other than its author.'));
    if (c?.headline) console.log(dim('  ') + c.headline);
  } catch (e) {
    console.log(red('failed'));
    console.error(dim('  ') + (e?.message || String(e)));
    process.exitCode = 1;
  }
}

const DESIGN_DOC_RE = /\.(md|markdown|txt|rst|adoc)$/i;

const DESIGN_MAX_DOCS = 50;

function walkDesignDocs(root) {
  const found = [];
  const stack = [root];
  while (stack.length && found.length < DESIGN_MAX_DOCS) {
    const dir = stack.pop();
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const ent of entries) {
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) { if (!SKIP_DIRS.has(ent.name)) stack.push(full); continue; }
      if (!DESIGN_DOC_RE.test(ent.name)) continue;
      found.push({ full, rel: path.relative(root, full).split(path.sep).join('/') });
      if (found.length >= DESIGN_MAX_DOCS) break;
    }
  }
  return found;
}

function printDesign(r) {
  const vColor = r.verdict === 'OPEN_PATH' ? red : yellow;
  console.log(bold(cyan('\n  Shomra design')) + dim(` - ${r.name}`));

  if (r.verdict === 'NOT_DESCRIBED') {
    console.log(`\n  ${yellow('• Nothing recognised')} ${dim('- no untrusted input, sensitive data, or agent action was described here.')}`);
    console.log(dim('    That is a statement about the document, not about the system. If the agent will read'));
    console.log(dim('    anything untrusted or take any action, write that down and re-run.\n'));
    return;
  }

  const capLine = (list, kind) =>
    list.length
      ? `  ${bold(kind)}  ${list.map((c) => CAP_LABEL[c]).join(dim(' · '))}`
      : `  ${bold(kind)}  ${dim('none described')}`;
  console.log('');
  console.log(capLine(r.sources, 'Sources'));
  console.log(capLine(r.sinks, 'Sinks  '));

  if (r.verdict === 'PARTIAL') {
    console.log(`\n  ${yellow('• Only one side of a path is described.')} ${dim('No closed path - yet.')}`);
    console.log(dim('    This is not a clean result: the other side may simply be unwritten, or land next sprint.\n'));
    return;
  }

  console.log(`\n  ${vColor(`✗ ${r.paths.length} attack path${r.paths.length === 1 ? '' : 's'} closed by this design:`)}\n`);
  for (const p of r.paths.slice(0, 6)) {
    const sc = SEV_COLOR[p.severity] || dim;
    console.log(`    ${sc(String(p.severity).padEnd(8))} ${bold(CAP_LABEL[p.source])} ${dim('→')} ${bold(CAP_LABEL[p.sink])}`);
    console.log(`             ${p.story}`);
    if (p.sourceEvidence) console.log(dim(`             ↳ line ${p.sourceEvidence.line}: "${p.sourceEvidence.quote}"`));
  }
  if (r.paths.length > 6) console.log(dim(`    … and ${r.paths.length - 6} more (run with --json for all)`));

  console.log(`\n  ${bold('Conditions to satisfy before this ships')}`);
  for (const c of r.controls.slice(0, 8)) console.log(`    ${dim('☐')} ${c.text}`);
  if (r.controls.length > 8) console.log(dim(`    … and ${r.controls.length - 8} more`));

  console.log(dim('\n  Paste these into the ticket: ') + bold(`shomra design ${r.name} --checklist`));
  console.log(dim('  It reads prose - it sees only what was written down. A capability nobody documented'));
  console.log(dim('  is not a capability you do not have.\n'));
}
