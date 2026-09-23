import fs from 'node:fs';
import { EXIT_USAGE } from '../core/exit-codes.mjs';
import { bold, cyan, dim, green, red, yellow } from '../core/terminal.mjs';
import { INDEX_FILE, SETTINGS_FILE, STATE_FILE, localBudgetMs, localDisabled, localSettings, patchState, readState, writeJson } from '../local/config.mjs';
import { ATTACK_EXEMPLARS, BENIGN_EXEMPLARS } from '../local/exemplars.mjs';
import { buildIndex, loadIndex, removeIndex, saveIndex } from '../local/index.mjs';
import { detectRuntime, findRuntime, normalizeUrl, urlLocality } from '../local/runtime.mjs';
import { indexProblem, screenWithLocalModel } from '../local/screen.mjs';
import { terminalSafe } from '../local/assist.mjs';
import { vetModel } from '../local/vet.mjs';

const EMBED_PREFERENCE = ['nomic-embed-text', 'mxbai-embed-large', 'snowflake-arctic-embed2', 'snowflake-arctic-embed', 'bge-m3', 'embeddinggemma', 'granite-embedding', 'all-minilm'];
const EMBED_RE = /embed|minilm|\bbge\b|bge-|\be5\b|\bgte\b|arctic/i;
const CHAT_PREFERENCE = ['qwen2.5-coder', 'qwen3-coder', 'qwen3', 'qwen2.5', 'llama3.2', 'llama3.1', 'gemma3', 'gemma2', 'phi4', 'phi3', 'mistral', 'deepseek-coder', 'codellama'];
const NOT_A_FIXER_RE = /guard|shield|embed|minilm|rerank|vision|llava|whisper/i;

function fail(message) {
  console.error(`\n  ${red('✗')} ${message}\n`);
  process.exit(EXIT_USAGE);
}

const baseName = (name) => String(name).split('/').pop().split(':')[0].toLowerCase();

function byPreference(models, preference, accept) {
  const pool = models.filter((m) => accept(m.name));
  for (const want of preference) {
    const hit = pool.find((m) => baseName(m.name) === want) ?? pool.find((m) => baseName(m.name).startsWith(want));
    if (hit) return hit.name;
  }
  return pool[0]?.name ?? null;
}

function resolveName(models, wanted) {
  const w = String(wanted).trim();
  return models.find((m) => m.name === w)?.name ?? models.find((m) => m.name === `${w}:latest`)?.name ?? null;
}

function usage() {
  console.log(`
  ${bold('shomra local')} ${dim('- use a model running on this machine (Ollama, LM Studio, llama.cpp) - no account, nothing leaves the machine')}

  ${bold('shomra local setup')}                  ${dim('find the runtime, vet + pin the models, calibrate the screen')}
      ${dim('--url <runtime>      default: tries Ollama :11434, LM Studio :1234, llama.cpp :8080')}
      ${dim('--embed <model>      the embedding model for the tool-result screen (e.g. nomic-embed-text)')}
      ${dim('--model <model>      the chat model for fix --local and why --local (e.g. qwen2.5-coder:3b)')}
      ${dim('--allow-remote       permit a runtime that is not on this machine or your private network')}
  ${bold('shomra local status')}                 ${dim('what is set up, whether it is reachable, and whether the pins still hold')}
  ${bold('shomra local test')} ${dim('<text> | --file <f>')}  ${dim('score a text the way the tool-result screen would')}
  ${bold('shomra local off')}                    ${dim('forget the local model')}

  ${dim('What it does: tool results are also read by the embedding model (raise-only: it can add a warning')}
  ${dim('for the agent, never block and never clear a finding), and fix/why can run with the chat model.')}
  ${dim('SHOMRA_LOCAL_OFF=1 turns it off for one shell; SHOMRA_LOCAL_BUDGET_MS caps the wait (default 250).')}
`);
}

function printVet(name, vet) {
  if (vet.error) console.log(`    ${yellow('!')} ${dim(`could not read ${name}'s template (${vet.error}) - not vetted`)}`);
  else if (!vet.read) console.log(`    ${yellow('!')} ${dim(`this runtime does not publish ${name}'s template - not vetted`)}`);
  for (const f of vet.findings) console.log(`    ${f.severity === 'CRITICAL' || f.severity === 'HIGH' ? red(f.severity) : yellow(f.severity)} ${f.title} ${dim(`(${f.where})`)}`);
}

async function setup(flags) {
  const explicit = typeof flags.url === 'string' && flags.url.trim() ? normalizeUrl(flags.url) : null;
  if (explicit) {
    const where = urlLocality(explicit);
    if (where === 'invalid') fail(`${bold(explicit)} is not an http(s) URL without credentials`);
    if (where === 'remote' && flags['allow-remote'] !== true) {
      fail(`${bold(explicit)} is not on this machine or your private network, and tool results would be sent there. ${dim('Pass --allow-remote if that is really what you want.')}`);
    }
  }

  console.log(`\n  ${bold(cyan('Shomra Local Model'))} ${dim('- setup')}`);
  const rt = explicit ? await detectRuntime(explicit) : await findRuntime();
  if (!rt) {
    console.log(`\n  ${yellow('!')} No model runtime answered${explicit ? ` at ${explicit}` : ' on this machine'}.`);
    console.log(`  ${dim('Install Ollama (https://ollama.com), then:')} ${bold('ollama pull nomic-embed-text')}`);
    console.log(`  ${dim('For fix/why on this machine too:')} ${bold('ollama pull qwen2.5-coder:3b')}`);
    console.log(`  ${dim('LM Studio or a llama.cpp server work as well - pass')} ${bold('--url http://127.0.0.1:<port>')}\n`);
    process.exit(EXIT_USAGE);
  }
  const locality = urlLocality(rt.url);
  console.log(`  ${green('✓')} ${rt.kind === 'ollama' ? 'Ollama' : 'OpenAI-compatible runtime'} at ${bold(rt.url)} ${dim(`· ${rt.models.length} model${rt.models.length === 1 ? '' : 's'}${locality === 'loopback' ? '' : ` · ${locality} network - text is redacted before it is sent`}`)}`);

  const embedName = flags.embed ? resolveName(rt.models, flags.embed) : byPreference(rt.models, EMBED_PREFERENCE, (n) => EMBED_RE.test(n));
  if (!embedName) {
    console.log(`\n  ${yellow('!')} ${flags.embed ? `${bold(String(flags.embed))} is not installed in this runtime.` : 'No embedding model is installed.'}`);
    console.log(`  ${dim('Pull one:')} ${bold('ollama pull nomic-embed-text')} ${dim('(or all-minilm for the fastest screen), then run this again.')}\n`);
    process.exit(EXIT_USAGE);
  }
  const judgeName = typeof flags.model === 'string' ? resolveName(rt.models, flags.model) : byPreference(rt.models, CHAT_PREFERENCE, (n) => !NOT_A_FIXER_RE.test(n));
  if (typeof flags.model === 'string' && !judgeName) fail(`${bold(flags.model)} is not installed in this runtime`);

  console.log(`\n  ${bold('Vetting')} ${dim('- a model whose template can execute code is refused')}`);
  const embedVet = await vetModel(rt, embedName);
  printVet(embedName, embedVet);
  if (embedVet.refused) fail(`${bold(embedName)} is refused: its template or Modelfile reaches the host. Use another embedding model.`);
  console.log(`    ${green('✓')} ${embedName} ${dim('(screen)')}`);
  let judge = judgeName;
  let judgeVet = null;
  if (judge) {
    judgeVet = await vetModel(rt, judge);
    printVet(judge, judgeVet);
    if (judgeVet.refused) {
      console.log(`    ${red('✗')} ${judge} ${dim('refused for fix/why')}`);
      judge = null;
    } else console.log(`    ${green('✓')} ${judge} ${dim('(fix / why)')}`);
  }

  process.stdout.write(`\n  ${dim(`Embedding ${ATTACK_EXEMPLARS.length + BENIGN_EXEMPLARS.length} reference samples and the calibration set with ${embedName}… `)}`);
  let built;
  try {
    built = await buildIndex(rt, embedName, { timeoutMs: 300_000 });
    console.log(green('done'));
  } catch (error) {
    console.log(red('failed'));
    fail(`${embedName} could not embed the reference samples (${terminalSafe(error.message, 200)})`);
  }
  saveIndex(built.stored);

  const digestOf = (name) => rt.models.find((m) => m.name === name)?.digest ?? null;
  const settings = {
    version: 1,
    kind: rt.kind,
    url: rt.url,
    locality,
    embed: { model: embedName, digest: digestOf(embedName), templateRead: !!embedVet.read },
    judge: judge ? { model: judge, digest: digestOf(judge), templateRead: !!judgeVet?.read } : null,
    setupAt: new Date().toISOString(),
  };
  writeJson(SETTINGS_FILE, settings);
  patchState({ backoffUntil: 0, lastError: null, modelChangedAt: null });

  const cal = built.calibration;
  console.log(`\n  ${bold('Calibration')} ${dim('(held-out samples the index was not built from)')}`);
  console.log(`    ${cal.usable ? green('✓') : yellow('!')} caught ${bold(`${Math.round(cal.recall * cal.attacks)} of ${cal.attacks}`)} attack samples with ${bold(`0 of ${cal.benign}`)} ordinary samples firing ${dim('- the threshold is set so none of them do')}`);
  if (!cal.usable) {
    console.log(`    ${dim(`${embedName} does not separate attacks from ordinary text well enough, so the tool-result screen stays off.`)}`);
    console.log(`    ${dim('Try')} ${bold('--embed nomic-embed-text')} ${dim('or')} ${bold('--embed mxbai-embed-large')}${dim('.')}`);
  }
  console.log('');
  if (cal.usable) console.log(`  ${green('✓')} Tool results are now also read by ${bold(embedName)} ${dim(`(raise-only · ${localBudgetMs()}ms budget · on this machine)`)}`);
  if (settings.judge) console.log(`  ${green('✓')} ${bold('shomra fix --local')} and ${bold('shomra why --local')} use ${bold(settings.judge.model)}`);
  else console.log(`  ${dim('No chat model for fix/why - pull one (ollama pull qwen2.5-coder:3b) and run setup again.')}`);
  console.log('');
}

async function describe() {
  const s = localSettings();
  if (!s) return { setup: false };
  const index = loadIndex();
  const problem = indexProblem(index, s);
  const rt = await detectRuntime(s.url, { timeoutMs: 1_500 });
  const installed = (name) => rt?.models.find((m) => m.name === name) ?? null;
  const pin = (m) => {
    if (!m) return null;
    const now = installed(m.model);
    if (!rt) return 'unreachable';
    if (!now) return 'missing';
    if (!m.digest) return 'unpinned';
    return now.digest === m.digest ? 'held' : 'changed';
  };
  const state = readState();
  return {
    setup: true,
    runtime: { kind: s.kind, url: s.url, locality: s.locality, reachable: !!rt },
    screen: { model: s.embed.model, pin: pin(s.embed), templateRead: s.embed.templateRead, problem, calibration: index?.calibration ?? null, budgetMs: localBudgetMs(), disabled: localDisabled() },
    judge: s.judge ? { model: s.judge.model, pin: pin(s.judge), templateRead: s.judge.templateRead } : null,
    lastError: state.lastError ? { message: state.lastError, at: state.lastErrorAt ? new Date(state.lastErrorAt).toISOString() : null } : null,
    modelChangedAt: state.modelChangedAt ? new Date(state.modelChangedAt).toISOString() : null,
  };
}

const PROBLEM_TEXT = {
  'no-index': 'the reference index is missing - run shomra local setup',
  'stale-index': 'the reference samples changed with this CLI version - run shomra local setup',
  'not-discriminative': 'the embedding model did not separate attacks from ordinary text at setup',
};

const PIN_TEXT = {
  held: green('pinned, unchanged'),
  changed: red('digest CHANGED since setup'),
  missing: red('no longer installed'),
  unpinned: yellow('this runtime publishes no digest'),
  unreachable: yellow('runtime not reachable'),
};

async function status(flags) {
  const d = await describe();
  if (flags.json) return console.log(JSON.stringify(d, null, 2));
  console.log(`\n  ${bold(cyan('Shomra Local Model'))}`);
  if (!d.setup) {
    console.log(`  ${dim('Not set up. Run')} ${bold('shomra local setup')} ${dim('- free, no account, nothing leaves this machine.')}\n`);
    return;
  }
  const on = !d.screen.disabled && !d.screen.problem && d.screen.pin !== 'missing';
  console.log(`  Runtime    ${d.runtime.kind === 'ollama' ? 'Ollama' : 'OpenAI-compatible'} at ${d.runtime.url} ${d.runtime.reachable ? green('· reachable') : red('· NOT reachable')}`);
  console.log(`  Screen     ${bold(d.screen.model)} ${dim('·')} ${PIN_TEXT[d.screen.pin] ?? ''} ${dim('· every answer is checked against a pinned probe, so a different model is never used silently')}`);
  if (d.screen.calibration) {
    const c = d.screen.calibration;
    console.log(`             ${dim(`caught ${Math.round(c.recall * c.attacks)} of ${c.attacks} held-out attacks · 0 of ${c.benign} ordinary samples fired · budget ${d.screen.budgetMs}ms`)}`);
  }
  console.log(`             ${on ? green('ON - raise-only on tool results') : yellow(`OFF - ${d.screen.disabled ? 'SHOMRA_LOCAL_OFF is set' : PROBLEM_TEXT[d.screen.problem] ?? 'the pinned model is not available'}`)}`);
  console.log(`  Fix / Why  ${d.judge ? `${bold(d.judge.model)} ${dim('·')} ${PIN_TEXT[d.judge.pin] ?? ''}${d.judge.pin === 'changed' ? red(' - refused until you run shomra local setup') : ''}` : dim('no chat model set up')}`);
  if (d.lastError) console.log(`  ${yellow('Last error')} ${dim(`${terminalSafe(d.lastError.message, 160)} (${d.lastError.at})`)}`);
  if (d.modelChangedAt) console.log(`  ${red('Model changed')} ${dim(`answers stopped matching the pinned model at ${d.modelChangedAt} - run shomra local setup`)}`);
  console.log('');
}

function readTestInput(flags, rest) {
  if (typeof flags.file === 'string') {
    try {
      return fs.readFileSync(flags.file, 'utf8');
    } catch (error) {
      fail(`cannot read ${flags.file}: ${error.message}`);
    }
  }
  if (rest.length) return rest.join(' ');
  if (!process.stdin.isTTY) return fs.readFileSync(0, 'utf8');
  return fail(`Usage: ${bold('shomra local test "<text>"')} ${dim('or --file <path>')}`);
}

async function test(flags, rest) {
  const s = localSettings();
  if (!s) fail(`Not set up. Run ${bold('shomra local setup')} first.`);
  const text = readTestInput(flags, rest);
  const reading = await screenWithLocalModel(text, s, { budgetMs: 15_000, ignoreBackoff: true, windows: { max: 12 } });
  if (flags.json) return console.log(JSON.stringify(reading, null, 2));
  console.log(`\n  ${bold(cyan('Shomra Local Model'))} ${dim(`- ${s.embed.model}`)}`);
  if (!Array.isArray(reading.windows)) {
    console.log(`  ${yellow('!')} No reading: ${reading.state}${reading.error ? dim(` (${terminalSafe(reading.error, 160)})`) : ''}\n`);
    return;
  }
  if (!reading.windows.length) console.log(`  ${dim('Nothing in this text addresses an agent, so the model was not asked.')}`);
  const cal = loadIndex()?.calibration;
  for (const w of reading.windows) {
    const hit = cal && w.att >= cal.threshold && w.margin >= cal.margin;
    console.log(`  ${hit ? red('● Raised') : dim('○ Quiet ')}  ${dim(`attack ${w.att.toFixed(3)} · margin ${w.margin >= 0 ? '+' : ''}${w.margin.toFixed(3)}`)}  ${terminalSafe(w.window, 140)}`);
  }
  if (cal) console.log(dim(`\n  Raises when attack ≥ ${cal.threshold.toFixed(3)} and margin ≥ ${cal.margin.toFixed(3)} (set at calibration).`));
  console.log(`  ${reading.state === 'raised' ? red('Raised - the agent would be told to treat this as data.') : green('Quiet - nothing would be added.')}\n`);
}

function off() {
  for (const f of [SETTINGS_FILE, STATE_FILE]) {
    try {
      fs.rmSync(f, { force: true });
    } catch {
    }
  }
  removeIndex(INDEX_FILE);
  console.log(`\n  ${green('✓')} Local model forgotten. ${dim('The models themselves stay installed in your runtime.')}\n`);
}

export async function cmdLocal(flags, positional = []) {
  const [sub, ...rest] = positional;
  if (flags.help || !sub) return usage();
  if (sub === 'setup') return setup(flags);
  if (sub === 'status') return status(flags);
  if (sub === 'test') return test(flags, rest);
  if (sub === 'off') return off();
  return fail(`Unknown subcommand ${bold(sub)} ${dim('- setup, status, test or off')}`);
}
