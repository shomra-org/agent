import os from 'node:os';
import path from 'node:path';
import { loadConfig } from '../core/config.mjs';
import { bold, cyan, dim, green, red, yellow } from '../core/terminal.mjs';
import { localGate } from '../detect/guard-signals.mjs';
import { discoverAll } from '../inventory/discovery.mjs';

const MAX_ISSUES_SHOWN = 6;
const UNGUARDED_AGENT_PENALTY = 8;
const MAX_UNGUARDED_PENALTY = 40;
const BLOCK_PENALTY = 15;
const FLAG_PENALTY = 5;
const DOTENV_KEY_PENALTY = 10;
const MAX_DOTENV_PENALTY = 30;

function assetPath(asset) {
  return asset.identifier || asset.metadata?.configFile || asset.metadata?.file || asset.name;
}

function riskyArtifactsIn(assets, kind) {
  const risky = [];
  for (const asset of assets) {
    const content = asset.content || asset.metadata?.content;
    if (!content) continue;
    const location = assetPath(asset);
    const verdict = localGate(content, { kind, path: location });
    if (verdict.verdict === 'ALLOW') continue;
    risky.push({
      name: asset.name,
      kind,
      decision: verdict.verdict,
      riskScore: verdict.riskScore,
      top: (verdict.findings[0] || {}).title,
      path: location,
    });
  }
  return risky;
}

function dedupeRisky(risky) {
  const seen = new Set();
  return risky.filter((entry) => {
    const key = `${entry.path}|${entry.decision}|${entry.top}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function groupIntoIssues(risky) {
  const byIssue = new Map();
  for (const entry of risky) {
    const key = `${entry.name}|${entry.kind}|${entry.decision}|${entry.top}`;
    const group = byIssue.get(key) ?? {
      name: entry.name, kind: entry.kind, decision: entry.decision, top: entry.top, riskScore: entry.riskScore, paths: [],
    };
    group.paths.push(entry.path);
    byIssue.set(key, group);
  }
  return [...byIssue.values()];
}

function postureScore({ unguarded, issues, dotenvKeys }) {
  let score = 100;
  score -= Math.min(MAX_UNGUARDED_PENALTY, unguarded.length * UNGUARDED_AGENT_PENALTY);
  for (const issue of issues) score -= issue.decision === 'BLOCK' ? BLOCK_PENALTY : FLAG_PENALTY;
  score -= Math.min(MAX_DOTENV_PENALTY, dotenvKeys.length * DOTENV_KEY_PENALTY);
  return Math.max(0, Math.round(score));
}

function postureGrade(score) {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

function scoreColour(score) {
  if (score >= 75) return green;
  if (score >= 50) return yellow;
  return red;
}

function collectInventory() {
  const assets = discoverAll();
  const ofType = (type) => assets.filter((asset) => asset.type === type);
  return {
    agents: ofType('AI_AGENT'),
    mcpServers: ofType('MCP_SERVER'),
    rulesFiles: ofType('AI_RULES'),
    modelKeys: ofType('MODEL_KEY'),
    aiTools: ofType('AI_TOOL'),
  };
}

function printCountRow(label, count, note) {
  console.log(`  ${dim(String(label).padEnd(16))} ${bold(String(count).padStart(3))}${note ? `  ${note}` : ''}`);
}

function printInventoryRows({ inventory, risky, unguarded, dotenvKeys }) {
  const riskyOfKind = (kind) => risky.filter((entry) => entry.kind === kind).length;
  const { agents, mcpServers, rulesFiles, modelKeys, aiTools } = inventory;

  printCountRow('Coding agents', agents.length, unguarded.length
    ? red(`${unguarded.length} UNGUARDED`) + dim(` · ${agents.length - unguarded.length} protected`)
    : green('all protected'));
  printCountRow('MCP servers', mcpServers.length, riskyOfKind('mcp') ? yellow(`${riskyOfKind('mcp')} risky`) : '');
  printCountRow('Rules files', rulesFiles.length, riskyOfKind('rules') ? yellow(`${riskyOfKind('rules')} risky`) : '');
  printCountRow('Model keys', modelKeys.length, dotenvKeys.length ? yellow(`${dotenvKeys.length} in .env files`) : '');
  printCountRow('AI tools', aiTools.length, '');
}

function printRiskyIssues(issues) {
  if (!issues.length) return;
  console.log(dim('\n  Risky artifacts:'));

  const shortDir = (target) => path.dirname(String(target || '')).replace(os.homedir(), '~').split(path.sep).join('/');
  const shown = issues.slice(0, MAX_ISSUES_SHOWN);
  for (const issue of shown) {
    const colour = issue.decision === 'BLOCK' ? red : yellow;
    const location = shortDir(issue.paths[0]);
    const where = issue.paths.length > 1
      ? dim(`×${issue.paths.length}`) + dim(` · ${location}, …`)
      : dim(location);
    console.log(`    ${colour('●')} ${bold(issue.name)} ${where} ${dim(`(${issue.kind})`)} ${colour(issue.decision)} ${dim(issue.top || '')}`);
  }

  const remaining = issues.length - shown.length;
  if (remaining > 0) console.log(dim(`    …and ${remaining} more distinct issue${remaining > 1 ? 's' : ''}`));
}

function topFixes({ unguarded, issues, risky, dotenvKeys }) {
  const fixes = [];
  if (unguarded.length) {
    fixes.push(`${red('!')} ${unguarded.length} coding agent${unguarded.length > 1 ? 's have' : ' has'} no runtime firewall → ${bold('shomra protect')}`);
  }
  if (issues.length) {
    const spread = risky.length > issues.length ? dim(` across ${risky.length} files`) : '';
    fixes.push(`${yellow('!')} ${issues.length} risky MCP/rules issue${issues.length > 1 ? 's' : ''}${spread} → ${bold('shomra check')} ${dim('or')} ${bold('shomra gate <file>')}`);
  }
  if (dotenvKeys.length) {
    fixes.push(`${yellow('!')} ${dotenvKeys.length} model key${dotenvKeys.length > 1 ? 's' : ''} in .env file${dotenvKeys.length > 1 ? 's' : ''} → rotate + ensure .gitignore covers them`);
  }
  return fixes;
}

function printFixes(fixes) {
  if (!fixes.length) {
    console.log(green('\n  ✓ No urgent fixes - nice posture.'));
    return;
  }
  console.log(bold('\n  Top fixes:'));
  for (const fix of fixes) console.log(`    ${fix}`);
}

function printEnrollmentHint() {
  const enrolled = !!loadConfig().apiKey;
  const message = enrolled
    ? `Enrolled - run ${bold('shomra report')}${dim(' to sync this to your Shomra org.')}`
    : `Run ${bold('shomra init')}${dim(' to apply org policy and sync posture.')}`;
  console.log(`${dim(`\n  ${message}`)}\n`);
}

function jsonReport({ inventory, score, grade, risky, issues, unguarded, dotenvKeys }) {
  return {
    score,
    grade,
    hostname: os.hostname(),
    codingAgents: inventory.agents.length,
    unguarded: unguarded.length,
    mcpServers: inventory.mcpServers.length,
    rulesFiles: inventory.rulesFiles.length,
    aiTools: inventory.aiTools.length,
    modelKeys: inventory.modelKeys.length,
    modelKeysInDotenv: dotenvKeys.length,
    riskyArtifacts: risky.length,
    riskyIssues: issues.length,
    risky,
  };
}

export function cmdDoctor(flags) {
  const inventory = collectInventory();
  const risky = dedupeRisky([
    ...riskyArtifactsIn(inventory.mcpServers, 'mcp'),
    ...riskyArtifactsIn(inventory.rulesFiles, 'rules'),
  ]);
  const issues = groupIntoIssues(risky);
  const unguarded = inventory.agents.filter((agent) => !agent.metadata?.guarded);
  const dotenvKeys = inventory.modelKeys.filter((key) => key.metadata?.source === 'dotenv');

  const score = postureScore({ unguarded, issues, dotenvKeys });
  const grade = postureGrade(score);

  if (flags.json) {
    console.log(JSON.stringify(jsonReport({ inventory, score, grade, risky, issues, unguarded, dotenvKeys }), null, 2));
    return;
  }

  const colour = scoreColour(score);
  console.log(bold(cyan('\n  Shomra doctor')) + dim(` - ${os.hostname()}`));
  console.log(`\n  ${bold('Posture')}  ${colour(bold(`${score}/100`))} ${dim('· grade')} ${colour(bold(grade))}\n`);

  printInventoryRows({ inventory, risky, unguarded, dotenvKeys });
  printRiskyIssues(issues);
  printFixes(topFixes({ unguarded, issues, risky, dotenvKeys }));
  printEnrollmentHint();
}
