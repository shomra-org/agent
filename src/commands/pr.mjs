import { execSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { ARTIFACT_MATCHERS, walkArtifacts } from '../artifacts/matchers.mjs';
import { loadConfig, resolveSettings } from '../core/config.mjs';
import { EXIT_USAGE } from '../core/exit-codes.mjs';
import { bold, cyan, dim, green, red, yellow } from '../core/terminal.mjs';
import { gateArtifactList } from '../gate/batch.mjs';
import { detectEnv } from '../gate/environment.mjs';
import { toSarif } from '../gate/sarif.mjs';

const PR_WORKFLOW = `name: Shomra AI Security
on: pull_request
permissions:
  contents: read
  checks: write
jobs:
  shomra:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }   # full history so the PR diff resolves
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - run: npx @shomra/agent pr
        env:
          GITHUB_TOKEN: \${{ secrets.GITHUB_TOKEN }}
          SHOMRA_API_KEY: \${{ secrets.SHOMRA_API_KEY }}   # optional - applies org policy
          SHOMRA_URL: \${{ secrets.SHOMRA_URL }}           # optional - your backend
`;

function readGithubEvent() {
  try { return JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8')); } catch { return {}; }
}

async function githubApi(token, method, apiPath, body) {
  const res = await fetch(`https://api.github.com${apiPath}`, {
    method,
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'Content-Type': 'application/json', 'User-Agent': 'shomra-agent' },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(`GitHub ${method} ${apiPath} → ${res.status} ${(await res.text()).slice(0, 200)}`);
  return res.json();
}

function gitChangedVsBase(root, base) {
  const run = (args) => { try { return execSync(`git ${args}`, { cwd: root, stdio: ['ignore', 'pipe', 'ignore'], timeout: 5000 }).toString(); } catch { return null; } };
  let out = null;
  for (const b of [`origin/${base}`, base]) {
    out = run(`diff --name-only --relative --diff-filter=ACM ${b}...HEAD`);
    if (out !== null) break;
  }
  if (out === null) out = run('diff HEAD~1 --name-only --relative --diff-filter=ACM');
  if (out === null) return null;
  const files = out.split('\n').map((s) => s.trim()).filter(Boolean);
  return files.filter((rel) => ARTIFACT_MATCHERS.some((m) => m.re.test(rel)));
}

const GH_LEVEL = { CRITICAL: 'failure', HIGH: 'failure', MEDIUM: 'warning', LOW: 'notice', INFO: 'notice' };

const CHECK_RUN_NAME = 'Shomra AI Security';
const MAX_ANNOTATIONS = 50;

function writeWorkflow(flags) {
  const workflow = path.resolve('.github/workflows/shomra.yml');
  if (fs.existsSync(workflow) && !flags.force) {
    console.error(`${red('✗')} ${path.relative(process.cwd(), workflow)} exists. Use ${bold('--force')}.`);
    process.exit(EXIT_USAGE);
  }
  fs.mkdirSync(path.dirname(workflow), { recursive: true });
  fs.writeFileSync(workflow, PR_WORKFLOW);
  console.log(`\n  ${green('✓ Wrote')} ${bold('.github/workflows/shomra.yml')} ${dim('- commit it; PRs will get an inline Shomra review.')}`);
  console.log(`${dim('  Optional: add ') + bold('SHOMRA_API_KEY') + dim(' as a repo secret to also apply org policy.')}\n`);
}

function headShaFromGit() {
  try {
    return execSync('git rev-parse HEAD', { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();
  } catch {
    return null;
  }
}

function resolvePrContext(flags) {
  const event = readGithubEvent();
  const context = {
    repo: flags.repo || process.env.GITHUB_REPOSITORY,
    token: flags.token || process.env.SHOMRA_GH_TOKEN || process.env.GITHUB_TOKEN,
    base: flags.base || process.env.GITHUB_BASE_REF || event.pull_request?.base?.ref || 'main',
    headSha: flags.sha || event.pull_request?.head?.sha || process.env.GITHUB_SHA || headShaFromGit(),
    prNumber: flags.pr || event.pull_request?.number || (String(process.env.GITHUB_REF || '').match(/refs\/pull\/(\d+)\//) || [])[1],
    root: path.resolve(flags.path || '.'),
    dryRun: !!flags['dry-run'],
  };

  if (!context.repo || !context.headSha) {
    console.error(`${red('✗')} Not in a GitHub PR context (need GITHUB_REPOSITORY + a head sha). Pass --repo / --sha, or use --dry-run.`);
    process.exit(EXIT_USAGE);
  }
  if (!context.token && !context.dryRun) {
    console.error(`${red('✗')} No GitHub token. Set GITHUB_TOKEN (CI) or --token, or preview with --dry-run.`);
    process.exit(EXIT_USAGE);
  }
  return context;
}

function emitSarif(flags, results) {
  if (!flags.sarif) return;
  const sarif = JSON.stringify(toSarif(results), null, 2);
  if (typeof flags.sarif === 'string') {
    fs.writeFileSync(path.resolve(String(flags.sarif)), sarif);
    if (!flags.json) console.error(dim(`  SARIF written → ${flags.sarif}`));
    return;
  }
  console.log(sarif);
}

function buildAnnotations(results) {
  const annotations = [];
  for (const result of results) {
    for (const finding of result.findings || []) {
      annotations.push({
        path: finding.file || result.path,
        start_line: finding.line || 1,
        end_line: finding.line || 1,
        annotation_level: GH_LEVEL[finding.severity] || 'warning',
        title: `${finding.severity}: ${result.kind}`,
        message: [
          finding.title,
          finding.remediationText ? `Fix: ${finding.remediationText}` : '',
          `Run \`shomra fix ${result.path}\` to remediate.`,
        ].filter(Boolean).join('\n'),
      });
    }
  }
  return annotations;
}

function checkRunConclusion(blocked, flagged, strict) {
  if (blocked) return 'failure';
  if (flagged) return strict ? 'failure' : 'neutral';
  return 'success';
}

function checkRunSummary({ results, annotations, blocked, flagged, suppressed }) {
  const headline = blocked ? `**${blocked} blocked**` : flagged ? `**${flagged} flagged**` : '**All clear**';
  const suppressedNote = suppressed ? ` · ${suppressed} suppressed` : '';
  return [
    headline,
    `· ${results.length} artifact(s) changed · ${annotations.length} finding(s)${suppressedNote}`,
    '',
    '| Artifact | Kind | Verdict | Findings |',
    '| --- | --- | --- | --- |',
    ...results.map((r) => `| \`${r.path}\` | ${r.kind} | ${r.decision} | ${(r.findings || []).length} |`),
    annotations.length > MAX_ANNOTATIONS ? `\n_Showing first ${MAX_ANNOTATIONS} of ${annotations.length} annotations._` : '',
  ].join('\n');
}

function buildCheckRun({ headSha, results, annotations, blocked, flagged, suppressed, strict }) {
  const verdict = blocked ? `${blocked} blocked` : flagged ? `${flagged} flagged` : 'Clean';
  return {
    name: CHECK_RUN_NAME,
    head_sha: headSha,
    status: 'completed',
    conclusion: checkRunConclusion(blocked, flagged, strict),
    output: {
      title: `${verdict} - ${results.length} changed artifact(s)`,
      summary: checkRunSummary({ results, annotations, blocked, flagged, suppressed }),
      annotations: annotations.slice(0, MAX_ANNOTATIONS),
    },
  };
}

async function postCheckRun(token, repo, checkRun, flags) {
  try {
    const run = await githubApi(token, 'POST', `/repos/${repo}/check-runs`, checkRun);
    if (flags.json) return;
    const mark = checkRun.conclusion === 'failure' ? red('✗') : checkRun.conclusion === 'neutral' ? yellow('⚠') : green('✓');
    console.log(`  ${mark} Check run posted → ${dim(run.html_url || '')}`);
  } catch (error) {
    console.error(`  ${yellow('⚠')} ${dim(`could not post check-run: ${error.message}`)}`);
  }
}

async function reportNothingChanged({ flags, token, dryRun, repo, headSha }) {
  emitSarif(flags, []);
  if (!flags.json && flags.sarif !== true) console.log(green('\n  ✓ No AI artifacts changed in this PR.\n'));
  if (!token || dryRun) return;

  await githubApi(token, 'POST', `/repos/${repo}/check-runs`, {
    name: CHECK_RUN_NAME,
    head_sha: headSha,
    status: 'completed',
    conclusion: 'success',
    output: {
      title: 'No AI artifacts changed',
      summary: 'No MCP configs, skills, rules, hooks or agent cards changed in this PR.',
    },
  }).catch((error) => console.error(dim(`  check-run: ${error.message}`)));
}

export async function cmdPr(flags, positional) {
  if (flags.init) {
    writeWorkflow(flags);
    return;
  }

  const { apiKey, url } = resolveSettings(loadConfig());
  const { repo, token, base, headSha, prNumber, root, dryRun } = resolvePrContext(flags);

  const changed = gitChangedVsBase(root, base);
  const allArtifacts = walkArtifacts(root);
  const artifacts = changed === null
    ? allArtifacts
    : allArtifacts.filter((artifact) => new Set(changed).has(artifact.rel));

  if (!artifacts.length) {
    await reportNothingChanged({ flags, token, dryRun, repo, headSha });
    return;
  }

  const { results, blocked, flagged, suppressed } = await gateArtifactList(artifacts, {
    apiKey, url, root, env: detectEnv(), flags: { ...flags, json: true },
  });
  emitSarif(flags, results);

  const annotations = buildAnnotations(results);
  const checkRun = buildCheckRun({ headSha, results, annotations, blocked, flagged, suppressed, strict: flags.strict });

  if (dryRun || flags.json) {
    console.log(JSON.stringify({
      repo,
      prNumber: prNumber ?? null,
      headSha,
      base,
      conclusion: checkRun.conclusion,
      artifacts: results.length,
      findings: annotations.length,
      checkRun: dryRun ? checkRun : undefined,
    }, null, 2));
  } else if (flags.sarif !== true) {
    console.log(bold(cyan('\n  Shomra pr')) + dim(` - ${repo} #${prNumber ?? '?'} · ${results.length} changed artifact(s) · ${annotations.length} finding(s)`));
  }

  if (token && !dryRun) await postCheckRun(token, repo, checkRun, flags);

  if (blocked) process.exitCode = 1;
  else if (flagged && flags.strict) process.exitCode = 2;
}
