import fs from 'node:fs';
import path from 'node:path';
import { CORPUS_DEFAULT_CHUNK, collectCorpusFiles, screenCorpus } from '../corpus/screening.mjs';
import { EXIT_USAGE } from '../core/exit-codes.mjs';
import { clampInt } from '../core/numbers.mjs';
import { SEV_COLOR, bold, cyan, dim, green, red, yellow } from '../core/terminal.mjs';

const MIN_CHUNK = 100;
const MAX_CHUNK = 100000;

const plural = (count, word) => `${word}${count === 1 ? '' : 's'}`;

function usageExit() {
  console.error(`${red('✗')} Usage: ${bold('shomra corpus <dir|file> [--chunk-size 1200] [--manifest <file>] [--strict]')}`);
  console.error(dim('  Screens documents BEFORE they are embedded, so a poisoned one never enters the index.'));
  process.exit(EXIT_USAGE);
}

function resolveTarget(flags, positional) {
  const target = positional[0] || flags.path;
  if (!target) usageExit();

  const absolutePath = path.resolve(String(target));
  if (!fs.existsSync(absolutePath)) {
    console.error(`${red('✗')} Not found: ${target}`);
    process.exit(EXIT_USAGE);
  }
  return { absolutePath, isDirectory: fs.statSync(absolutePath).isDirectory() };
}

function buildManifest({ absolutePath, isDirectory, chunkSize, results, unreadable, quarantined }) {
  return {
    root: isDirectory ? absolutePath : path.dirname(absolutePath),
    chunkSize,
    screened: results.length,
    unreadable: unreadable.length,
    quarantine: quarantined.map(({ path: file, verdict, findings }) => ({ path: file, verdict, findings })),
    unreadableFiles: unreadable.map(({ rel, reason }) => ({ path: rel, reason })),
  };
}

function writeManifest(flags, manifest) {
  if (!flags.manifest) return;
  const target = path.resolve(String(flags.manifest));
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, `${JSON.stringify(manifest, null, 2)}\n`);
}

function findingContext(finding) {
  if (finding.concealed) return yellow(' [hidden in an HTML comment - invisible to a reader, read by the model]');
  if (finding.codeContext) return dim(' [quoted in a code block]');
  return '';
}

function findingLocation(finding) {
  if (finding.chunk !== null && finding.chunk !== undefined) return dim(` (line ${finding.line} · chunk ${finding.chunk})`);
  return finding.line ? dim(` (line ${finding.line})`) : '';
}

function printQuarantined(quarantined) {
  for (const document of quarantined) {
    const colour = document.verdict === 'BLOCK' ? red : yellow;
    console.log(`\n  ${colour(document.verdict === 'BLOCK' ? '✗ QUARANTINE' : '⚠ REVIEW')} ${bold(document.path)}`);
    for (const finding of document.findings) {
      const severity = (SEV_COLOR[finding.severity] || dim)(String(finding.severity).padEnd(8));
      console.log(`    ${severity} ${finding.label}${findingLocation(finding)}${findingContext(finding)}`);
    }
  }
}

function summaryLine({ blocked, flagged, total }) {
  if (blocked.length) {
    const clean = total - blocked.length - flagged.length;
    return red(`✗ ${blocked.length} ${plural(blocked.length, 'document')} must not be indexed`)
      + dim(` · ${flagged.length} to review · ${clean} clean`);
  }
  if (flagged.length) {
    return yellow(`⚠ ${flagged.length} to review`) + dim(` · ${total - flagged.length} clean`);
  }
  return green(`✓ All ${total} screened documents clean.`);
}

function printUnreadable(unreadable) {
  if (!unreadable.length) return;
  const heading = `${unreadable.length} ${plural(unreadable.length, 'file')} could not be read`;
  console.log(`  ${yellow('⚠')} ${bold(heading)} ${dim('- they are NOT covered by the result above:')}`);

  const byReason = new Map();
  for (const entry of unreadable) byReason.set(entry.reason, (byReason.get(entry.reason) || 0) + 1);
  for (const [reason, count] of byReason) console.log(dim(`      ${count} × ${reason}`));
  console.log(dim('      Extract them to text and re-run, or exclude them from the index.'));
}

function printReport({ flags, chunkSize, results, unreadable, blocked, flagged, quarantined }) {
  console.log(bold(cyan('\n  Shomra corpus')) + dim(` - ${results.length} ${plural(results.length, 'document')} · chunk size ${chunkSize}`));
  printQuarantined(quarantined);
  console.log('');
  console.log(`  ${summaryLine({ blocked, flagged, total: results.length })}`);
  printUnreadable(unreadable);
  if (flags.manifest) console.log(dim(`  Quarantine manifest → ${flags.manifest}`));
  console.log(dim('  Feed the manifest to your ingestion job so a quarantined document is never embedded.\n'));
}

export async function cmdCorpus(flags, positional) {
  const { absolutePath, isDirectory } = resolveTarget(flags, positional);
  const chunkSize = clampInt(flags['chunk-size'], CORPUS_DEFAULT_CHUNK, MIN_CHUNK, MAX_CHUNK);

  const { files, opaque } = collectCorpusFiles(absolutePath, isDirectory);
  const { results, unreadable } = screenCorpus(files, opaque, chunkSize);

  const blocked = results.filter((document) => document.verdict === 'BLOCK');
  const flagged = results.filter((document) => document.verdict === 'FLAG');
  const quarantined = [...blocked, ...flagged];

  const manifest = buildManifest({ absolutePath, isDirectory, chunkSize, results, unreadable, quarantined });
  writeManifest(flags, manifest);

  if (flags.json) {
    console.log(JSON.stringify({ ...manifest, blocked: blocked.length, flagged: flagged.length, results }, null, 2));
  } else {
    printReport({ flags, chunkSize, results, unreadable, blocked, flagged, quarantined });
  }

  if (blocked.length) process.exitCode = 1;
  else if ((flagged.length || unreadable.length) && flags.strict) process.exitCode = 2;
}
