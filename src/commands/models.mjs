import path from 'node:path';
import { loadConfig, resolveSettings } from '../core/config.mjs';
import { clampInt } from '../core/numbers.mjs';
import { SEV_COLOR, bold, cyan, dim, gray, green, red, yellow } from '../core/terminal.mjs';
import { printAlternatives } from '../models/lookup.mjs';
import { assessModel, collectModelReferences, lookupModels, resolveScanScope } from '../models/references.mjs';
import { walkFiles } from './secrets.mjs';

const DEFAULT_CONCURRENCY = 6;
const MIN_CONCURRENCY = 1;
const MAX_CONCURRENCY = 16;
const MAX_LOCATIONS_SHOWN = 3;
const MAX_FINDINGS_SHOWN = 3;

function lookupUrl(url, reference) {
  const query = `id=${encodeURIComponent(reference.id)}${reference.sha ? `&sha=${reference.sha}` : ''}`;
  return `${url}/models/lookup?${query}`;
}

function printNothingFound(flags, root) {
  if (flags.json) {
    console.log(JSON.stringify({ detected: 0, models: [] }, null, 2));
    return;
  }
  const where = path.relative(process.cwd(), root).split(path.sep).join('/') || '.';
  console.log(`${green('\n  ✓ No AI model references found in the code.')}${dim(` (looked under ${where})`)}\n`);
}

function printDryRun(flags, references, url) {
  if (flags.json) {
    console.log(JSON.stringify({
      detected: references.length,
      models: references.map((reference) => ({
        id: reference.id,
        sha: reference.sha,
        source: reference.source,
        lookup: lookupUrl(url, reference),
        locations: reference.locations,
      })),
    }, null, 2));
    return;
  }
  console.log(bold(cyan('\n  Shomra models')) + dim(` - ${references.length} reference(s) detected (dry run - no lookup)`));
  for (const reference of references) {
    const revision = reference.sha ? dim(`@${reference.sha}`) : '';
    console.log(`  ${gray('•')} ${bold(reference.id)}${revision} ${dim(`(${reference.source})`)} ${dim(`→ ${url}/models/lookup?id=${reference.id}`)}`);
  }
  console.log('');
}

function statusLabel(model) {
  if (model.error) return yellow('lookup failed');
  if (model.notIndexed) {
    return dim(model.source === 'ollama' ? 'local runtime - not in the index' : 'not in the index yet');
  }
  const verdictColour = model.verdict === 'FAIL' ? red : model.verdict === 'REVIEW' ? yellow : green;
  return `${verdictColour(model.verdict)} ${dim(`risk ${model.riskScore} · ${model.findingCount} vuln(s)`)}`;
}

function alertMark(model) {
  if (model.alert === 'BLOCK') return red('●');
  if (model.alert === 'FLAG') return yellow('●');
  return model.notIndexed ? gray('○') : green('●');
}

function printModel(model) {
  const revision = model.sha ? dim(`@${String(model.sha).slice(0, 12)}`) : '';
  console.log(`  ${alertMark(model)} ${bold(model.id)}${revision} ${dim(`(${model.source})`)}  ${statusLabel(model)}`);

  const shown = model.locations.slice(0, MAX_LOCATIONS_SHOWN).map((l) => `${l.file}:${l.line}`).join(', ');
  const more = model.locations.length > MAX_LOCATIONS_SHOWN ? ` (+${model.locations.length - MAX_LOCATIONS_SHOWN})` : '';
  console.log(`      ${dim(`used in ${shown}${more}`)}`);

  for (const finding of model.findings.slice(0, MAX_FINDINGS_SHOWN)) {
    console.log(`      ${(SEV_COLOR[finding.severity] || dim)(String(finding.severity).padEnd(8))} ${finding.title}`);
  }
  printAlternatives(model.alternatives, 'model');

  if (model.notIndexed && model.source !== 'ollama') {
    console.log(`      ${dim('→ scan it now:')} ${bold(`shomra model-scan ${model.id}`)}`);
  }
}

function uncheckedNotice(models, url) {
  const failed = models.filter((model) => model.error).length;
  if (!failed) return null;
  const why = url ? ' (model index unreachable)' : ' (no backend configured - set SHOMRA_URL)';
  return yellow(`⚠ ${failed} model reference(s) could not be checked`) + dim(why);
}

function summaryLine({ models, blocked, flagged, url }) {
  const unchecked = uncheckedNotice(models, url);
  const suffix = unchecked ? ` · ${unchecked}` : '';
  if (blocked) return red(`✗ ${blocked} vulnerable`) + dim(` · ${flagged} to review`) + suffix;
  if (flagged) return yellow(`⚠ ${flagged} to review`) + suffix;
  return unchecked || green('✓ No known-vulnerable models');
}

function printReport({ models, blocked, flagged, url, indexUnreachable }) {
  const indexNote = url ? ` · index at ${url}` : ' · local detection only';
  console.log(bold(cyan('\n  Shomra models')) + dim(` - ${models.length} model reference(s)${indexNote}`));

  if (indexUnreachable) {
    const why = url
      ? 'Model index unreachable - could not fetch vulnerability info.'
      : 'Model index not configured - set SHOMRA_URL to check models against the Shomra Model Index.';
    console.log(`  ${yellow('⚠')} ${dim(why)}`);
  }

  for (const model of models) printModel(model);
  console.log(`\n  ${summaryLine({ models, blocked, flagged, url })}\n`);
}

export async function cmdModels(flags, positional) {
  const { url } = resolveSettings(loadConfig());
  const target = path.resolve(positional[0] || flags.path || '.');

  const { root, entries } = resolveScanScope(target, walkFiles);
  const references = collectModelReferences(root, entries);

  if (!references.length) {
    printNothingFound(flags, root);
    return;
  }
  if (flags['dry-run']) {
    printDryRun(flags, references, url);
    return;
  }

  const concurrency = clampInt(process.env.SHOMRA_GATE_CONCURRENCY, DEFAULT_CONCURRENCY, MIN_CONCURRENCY, MAX_CONCURRENCY);
  const { results, indexUnreachable } = await lookupModels(url, references, concurrency);
  const models = references.map((reference, index) => assessModel(reference, results[index]));

  const blocked = models.filter((model) => model.alert === 'BLOCK').length;
  const flagged = models.filter((model) => model.alert === 'FLAG').length;

  if (flags.json) {
    console.log(JSON.stringify({ detected: models.length, blocked, flagged, apiDown: indexUnreachable, url, models }, null, 2));
  } else {
    printReport({ models, blocked, flagged, url, indexUnreachable });
  }

  if (blocked) process.exitCode = 1;
  else if (flagged && flags.strict) process.exitCode = 2;
}
