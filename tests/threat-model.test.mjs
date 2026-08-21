// CLI-level tests for the OWASP threat-model refresh controls:
//   `shomra pr --threat-model`   — fail the build when the capability manifest
//                                   moved past its threat model
//   `shomra pr --init`           — scaffold the nine refresh-trigger questions
//   `shomra design --save`       — persist the model instead of printing it
//
// Each child runs against a LOCAL STUB backend rather than a real one, because
// the behaviour under test is entirely about how the CLI folds a verdict into a
// check-run conclusion and an exit code — and a test that needed a live backend
// is a test that gets skipped in CI, which is where this control runs.
//
// ⚠ THE CASE THAT MATTERS MOST is `no AI artifact changed + stale model`. The
// changes OWASP describes leave no dangerous artifact behind — a routing rule
// edited in application code, a model pinned in a deploy config — so a PR can
// move the manifest well past its threat model while touching not one MCP
// config. An implementation that returns early on "nothing to gate" skips the
// control precisely where it was needed and reports success. That is not a
// hypothetical: it is what this command did on the first pass.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(HERE, '..', 'shomra.mjs');
const fakeHome = fs.mkdtempSync(path.join(os.tmpdir(), 'shomra-tm-home-'));

const STALE = {
  conclusion: 'STALE',
  summary: '1 threat model(s) no longer describe the system',
  subjects: [
    {
      subjectKind: 'AGENT',
      subjectId: 'a1',
      conclusion: 'STALE',
      headline: 'Threat model is stale — 2 axes moved: Capabilities, Models.',
      drift: {
        deltas: [
          { axis: 'capabilities', label: 'Capabilities', meaning: 'APIs, plugins, MCP servers, commands.', drift: 'CHANGED' },
          { axis: 'models', label: 'Models', meaning: 'Model version, provider and routing.', drift: 'CHANGED' },
          { axis: 'memory', label: 'Memory & context', meaning: 'Retrieval sources.', drift: 'UNCHANGED' },
        ],
      },
    },
  ],
};
const PASS = {
  conclusion: 'PASS',
  summary: 'All 1 subject(s) are covered by an approved threat model.',
  subjects: [{ subjectKind: 'AGENT', subjectId: 'a1', conclusion: 'PASS', headline: 'covered', drift: { deltas: [] } }],
};
const NO_MODEL = {
  conclusion: 'NO_MODEL',
  summary: '1 subject(s) have no threat model',
  subjects: [{ subjectKind: 'AGENT', subjectId: 'a1', conclusion: 'NO_MODEL', headline: 'No threat model has been authored for this subject.', drift: null }],
};
const UNREVIEWED = {
  conclusion: 'UNREVIEWED',
  summary: '1 awaiting review',
  subjects: [{ subjectKind: 'AGENT', subjectId: 'a1', conclusion: 'UNREVIEWED', headline: 'The current threat model version is IN_REVIEW, not APPROVED.', drift: { deltas: [] } }],
};

/**
 * A stub backend, in ITS OWN PROCESS.
 *
 * ⚠ IT CANNOT LIVE IN THIS PROCESS. `run()` uses `spawnSync`, which blocks the
 * event loop for the child's whole lifetime — an in-process HTTP server would
 * never get a tick to answer with, so every request would hang until the spawn
 * timeout and each test would "fail" after 60s of deadlock rather than on its
 * assertion. Matching the rest of the suite's synchronous `run()` is worth more
 * than saving a process here.
 *
 * ⚠ ONLY `/threat-models/*` IS ANSWERED. The gate itself POSTs to this backend
 * too, and feeding it a threat-model verdict as if it were a gate result makes
 * the artifact analysis nonsense. A 404 on everything else is what an unenrolled
 * route looks like, so the gate falls back to its local verdict — which is the
 * behaviour these tests want to hold still while the threat-model half varies.
 */
const STUB_SRC = `
import http from 'node:http';
import fsx from 'node:fs';
const payload = JSON.parse(process.argv[2]);
const server = http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {
    if (!req.url.startsWith('/threat-models')) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ message: 'not found' }));
    }
    if (process.env.STUB_LOG) {
      try { fsx.appendFileSync(process.env.STUB_LOG, JSON.stringify({ url: req.url, method: req.method, body: body ? JSON.parse(body) : null }) + '\\n'); } catch {}
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(payload));
  });
});
server.listen(0, '127.0.0.1', () => process.stdout.write(String(server.address().port) + '\\n'));
`;

let stubFile = null;
function stubPath() {
  if (!stubFile) {
    stubFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'shomra-tm-stub-')), 'stub.mjs');
    fs.writeFileSync(stubFile, STUB_SRC);
  }
  return stubFile;
}

async function withStub(payload, fn, { log } = {}) {
  const env = { ...process.env };
  if (log) env.STUB_LOG = log;
  const child = spawn(process.execPath, [stubPath(), JSON.stringify(payload)], { env, stdio: ['ignore', 'pipe', 'inherit'] });
  const port = await new Promise((resolve, reject) => {
    let buf = '';
    const t = setTimeout(() => reject(new Error('stub did not start')), 10_000);
    child.stdout.on('data', (c) => {
      buf += c;
      if (buf.includes('\n')) {
        clearTimeout(t);
        resolve(Number(buf.trim()));
      }
    });
    child.on('error', reject);
  });
  try {
    return await fn(`http://127.0.0.1:${port}`);
  } finally {
    child.kill();
  }
}

function run(args, { cwd, url, key = 'shm_test' } = {}) {
  const env = { ...process.env, USERPROFILE: fakeHome, HOME: fakeHome, NO_COLOR: '1' };
  for (const k of Object.keys(env)) if (k.startsWith('SHOMRA_')) delete env[k];
  if (url) env.SHOMRA_URL = url;
  if (url) env.SHOMRA_API_KEY = key;
  const res = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', env, cwd: cwd || fakeHome, timeout: 60_000 });
  return { code: res.status, stdout: res.stdout ?? '', stderr: res.stderr ?? '' };
}

/** A repo with one gateable AI artifact. */
function repoWithArtifact() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shomra-tm-repo-'));
  fs.writeFileSync(path.join(dir, '.mcp.json'), JSON.stringify({ mcpServers: {} }));
  return dir;
}

/** A repo whose diff contains NO AI artifact — only application code. */
function repoWithoutArtifact() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shomra-tm-plain-'));
  fs.writeFileSync(path.join(dir, 'router.js'), "export const model = 'claude-opus-5';\n");
  return dir;
}

const PR_ARGS = ['pr', '--dry-run', '--repo', 'o/r', '--sha', 'abc123'];

function checkRunOf(stdout) {
  // --dry-run prints the computed check run as JSON, then the human line.
  const start = stdout.indexOf('{');
  assert.ok(start >= 0, `no JSON in output:\n${stdout}`);
  let depth = 0;
  for (let i = start; i < stdout.length; i++) {
    if (stdout[i] === '{') depth++;
    else if (stdout[i] === '}' && --depth === 0) return JSON.parse(stdout.slice(start, i + 1));
  }
  throw new Error(`unterminated JSON in output:\n${stdout}`);
}

test('pr --threat-model: a STALE model fails the check and exits 1', async () => {
  const cwd = repoWithArtifact();
  await withStub(STALE, (url) => {
    const r = run([...PR_ARGS, '--threat-model', 'AGENT:a1'], { cwd, url });
    assert.equal(r.code, 1, 'a stale threat model is a hard fail');
    const out = checkRunOf(r.stdout);
    assert.equal(out.conclusion, 'failure');
    // ⚠ The title is the only part a reviewer reads in the checks list. A red
    // check titled "Clean" contradicts its own conclusion.
    assert.match(out.checkRun.output.title, /Threat model out of date/);
  });
});

test('pr --threat-model: the summary NAMES the axes that moved', async () => {
  const cwd = repoWithArtifact();
  await withStub(STALE, (url) => {
    const r = run([...PR_ARGS, '--threat-model', 'AGENT:a1'], { cwd, url });
    const summary = checkRunOf(r.stdout).checkRun.output.summary;
    // "Your threat model is stale" without WHICH of the nine axes moved is a
    // notification, not a finding — the reader still has to go diff the world.
    assert.match(summary, /Capabilities/);
    assert.match(summary, /Models/);
    assert.match(summary, /Axes that moved/);
    assert.doesNotMatch(summary, /Memory & context/, 'an UNCHANGED axis must not be listed as moved');
  });
});

test('pr --threat-model: NO AI artifact changed + stale model STILL fails', async () => {
  // ⚠ THE REGRESSION THIS FILE EXISTS FOR. A routing rule edited in application
  // code moves the manifest and touches no MCP config; an early return on
  // "nothing to gate" skips the control exactly where it was needed.
  const cwd = repoWithoutArtifact();
  await withStub(STALE, (url) => {
    const r = run([...PR_ARGS, '--threat-model', 'AGENT:a1'], { cwd, url });
    assert.equal(r.code, 1, 'the gate must run even when no AI artifact changed');
    assert.match(r.stdout, /Threat model:/);
    assert.match(r.stdout, /no longer describe the system/);
  });
});

test('pr --threat-model: NO_MODEL fails — never authoring one is not a pass', async () => {
  const cwd = repoWithArtifact();
  await withStub(NO_MODEL, (url) => {
    const r = run([...PR_ARGS, '--threat-model', 'AGENT:a1'], { cwd, url });
    assert.equal(r.code, 1, 'otherwise the fastest route to green is to never write a threat model');
    assert.match(checkRunOf(r.stdout).checkRun.output.title, /no model authored/);
  });
});

test('pr --threat-model: PASS leaves the check green and exits 0', async () => {
  const cwd = repoWithArtifact();
  await withStub(PASS, (url) => {
    const r = run([...PR_ARGS, '--threat-model', 'AGENT:a1'], { cwd, url });
    assert.equal(r.code, 0);
    assert.equal(checkRunOf(r.stdout).conclusion, 'success');
  });
});

test('pr --threat-model: UNREVIEWED is neutral, not a failure', async () => {
  // A human step still in flight. Failing the build for it punishes the author
  // for their reviewer not having looked yet.
  const cwd = repoWithArtifact();
  await withStub(UNREVIEWED, (url) => {
    const r = run([...PR_ARGS, '--threat-model', 'AGENT:a1'], { cwd, url });
    assert.equal(r.code, 0);
    assert.equal(checkRunOf(r.stdout).conclusion, 'neutral');
  });
});

test('pr --threat-model: an unreachable backend is NEUTRAL, never a silent pass', () => {
  // Silently succeeding would make "break the network" the cheapest way past a
  // control whose entire purpose is to be unskippable.
  const cwd = repoWithArtifact();
  const r = run([...PR_ARGS, '--threat-model', 'AGENT:a1'], { cwd, url: 'http://127.0.0.1:1' });
  assert.equal(r.code, 0, 'our own inability to look must not fail the author’s build');
  const out = checkRunOf(r.stdout);
  assert.equal(out.conclusion, 'neutral', 'and it must not report success either');
  assert.match(r.stdout, /could not be checked/);
});

test('pr without --threat-model: behaviour is unchanged', async () => {
  const cwd = repoWithArtifact();
  await withStub(STALE, (url) => {
    const r = run(PR_ARGS, { cwd, url });
    assert.equal(r.code, 0);
    assert.equal(checkRunOf(r.stdout).conclusion, 'success');
    assert.doesNotMatch(r.stdout, /Threat model/, 'the gate is silent unless asked for');
  });
});

test('pr --init: scaffolds the PR template with all nine refresh axes', () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'shomra-tm-init-'));
  const r = run(['pr', '--init'], { cwd });
  assert.equal(r.code, 0);
  const tpl = fs.readFileSync(path.join(cwd, '.github', 'pull_request_template.md'), 'utf8');
  for (const axis of ['Capabilities', 'Authority', 'Instructions', 'Models', 'Memory / context', 'Oversight', 'Orchestration', 'External effects', 'Detection']) {
    assert.ok(tpl.includes(axis), `template is missing the ${axis} question`);
  }
  // ⚠ Every box starts UNTICKED. A template that pre-answers its own questions
  // teaches people to scroll past it.
  assert.ok(!/- \[x\]/i.test(tpl), 'no box may ship pre-ticked');
  assert.match(tpl, /other than its author/i, 'the named-external-reviewer step must be on the template');
  // The workflow still ships alongside it — the two halves are useless apart.
  assert.ok(fs.existsSync(path.join(cwd, '.github', 'workflows', 'shomra.yml')));
});

test('pr --init: an existing PR template is never overwritten without --force', () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'shomra-tm-keep-'));
  fs.mkdirSync(path.join(cwd, '.github'), { recursive: true });
  const mine = '## Our own template\n';
  fs.writeFileSync(path.join(cwd, '.github', 'pull_request_template.md'), mine);

  const r = run(['pr', '--init'], { cwd });
  assert.equal(r.code, 0);
  assert.equal(fs.readFileSync(path.join(cwd, '.github', 'pull_request_template.md'), 'utf8'), mine, 'a customised template must survive');
  assert.match(r.stdout, /already exists/);

  const forced = run(['pr', '--init', '--force'], { cwd });
  assert.equal(forced.code, 0);
  assert.match(fs.readFileSync(path.join(cwd, '.github', 'pull_request_template.md'), 'utf8'), /AI capability review/);
});

test('design --save: refuses without a subject rather than guessing one', () => {
  const r = run(['design', '-', '--save'], { cwd: fakeHome });
  assert.equal(r.code, 3, 'usage error');
  assert.match(r.stderr, /--subject/);
});

test('design --save: refuses when not enrolled', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shomra-tm-doc-'));
  const doc = path.join(dir, 'rfc.md');
  fs.writeFileSync(doc, 'The agent reads inbound emails and runs shell commands to fix things.\n');
  const r = run(['design', doc, '--save', '--subject', 'DESIGN:refunds'], { cwd: dir });
  assert.equal(r.code, 3);
  assert.match(r.stderr, /Not configured/);
});

test('design --save: posts the analysis and says approval is still required', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shomra-tm-doc2-'));
  const doc = path.join(dir, 'rfc.md');
  fs.writeFileSync(doc, 'The agent reads inbound customer emails and runs shell commands.\n');
  const log = path.join(dir, 'requests.jsonl');

  await withStub({ version: { seq: 1, reviewState: 'IN_REVIEW' }, coverage: { headline: 'Awaiting review.' } }, (url) => {
    const r = run(['design', doc, '--save', '--subject', 'DESIGN:refunds'], { cwd: dir, url });
    assert.match(r.stdout, /Saved.*threat model.*v1/s);
    // ⚠ Authoring is not approval. A user who thinks it is will read the next
    // red build as a bug in the tool.
    assert.match(r.stdout, /does NOT clear the CI gate/i);
    assert.match(r.stdout, /other than its author/i);

    const posts = fs
      .readFileSync(log, 'utf8')
      .split('\n')
      .filter(Boolean)
      .map((l) => JSON.parse(l));
    const post = posts.find((x) => x.url === '/threat-models');
    assert.ok(post, `the analysis must be POSTed; saw ${JSON.stringify(posts.map((p) => p.url))}`);
    assert.equal(post.body.subjectKind, 'DESIGN');
    assert.equal(post.body.subjectId, 'refunds');
    assert.equal(post.body.source, 'cli');
    assert.ok(post.body.analysis?.paths, 'the analysis travels with it');
    // ⚠ The manifest is taken server-side. A CLI that sent its own could pin a
    // model to a system it invented.
    assert.ok(!post.body.manifest, 'the CLI must not supply its own manifest');
  }, { log });
});
