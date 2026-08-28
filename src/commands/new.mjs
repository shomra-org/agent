import fs from 'node:fs';
import path from 'node:path';
import { EXIT_USAGE } from '../core/exit-codes.mjs';
import { bold, dim, green, red, yellow } from '../core/terminal.mjs';
import { localGate } from '../detect/guard-signals.mjs';
import { AGENT_FRAMEWORKS, agentProjectFiles } from '../scaffold/agent-project.mjs';
import { NEW_TEMPLATES } from '../scaffold/artifact-templates.mjs';

function cmdNewAgent(flags, positional) {
  const framework = String(flags.framework || AGENT_FRAMEWORKS[0]).toLowerCase();
  if (!AGENT_FRAMEWORKS.includes(framework)) {
    console.error(red('✗') + ` Unknown --framework: ${framework}. Supported: ${AGENT_FRAMEWORKS.join(', ')}.`);
    process.exit(EXIT_USAGE);
  }
  const name = (positional[0] || 'my-agent').replace(/[^a-zA-Z0-9._-]/g, '-');
  const dir = path.resolve(name);
  if (fs.existsSync(dir) && fs.readdirSync(dir).length && !flags.force) {
    console.error(red('✗') + ` ${name}/ already exists and is not empty. Use ${bold('--force')} to write into it anyway.`);
    process.exit(EXIT_USAGE);
  }

  const files = agentProjectFiles(name);
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(dir, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }

  if (flags.json) {
    console.log(JSON.stringify({ created: name, framework, files: Object.keys(files) }, null, 2));
    return;
  }
  console.log(`\n  ${green('✓ Created')} ${bold(name + '/')} ${dim('· ' + framework + ' · ' + Object.keys(files).length + ' files')}`);
  for (const rel of Object.keys(files)) console.log(`    ${dim('+')} ${rel}`);
  console.log(`\n  ${bold('Next')}`);
  console.log(`    cd ${name} && cp .env.example .env && npm install`);
  console.log(`    ${bold('shomra rules --write')} ${dim('- write the agent rules block into CLAUDE.md')}`);
  console.log(`    ${bold('shomra check')}         ${dim('- confirm it starts clean')}`);
  console.log(dim('\n  Guard enforcing, egress allowlisted, secrets in env, gate in CI - from commit zero.\n'));
}

export function cmdNew(flags, positional) {
  const kind = String(positional[0] || '').toLowerCase();

  if (kind === 'agent') return cmdNewAgent(flags, positional.slice(1));
  const tmpl = NEW_TEMPLATES[kind];
  if (!tmpl) {
    console.error(red('✗') + ` Usage: ${bold('shomra new ' + Object.keys(NEW_TEMPLATES).join('|') + '|agent [name]')}`);
    process.exit(EXIT_USAGE);
  }
  const name = (positional[1] || (kind === 'rules' ? 'rules' : `my-${kind}`)).replace(/[^a-zA-Z0-9._-]/g, '-');
  const { file, content } = tmpl(name);
  const target = path.resolve(file);
  if (fs.existsSync(target) && !flags.force) {
    console.error(red('✗') + ` ${file} already exists. Use ${bold('--force')} to overwrite.`);
    process.exit(EXIT_USAGE);
  }
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, content);
  const g = localGate(content, { kind: kind === 'agent-card' ? 'agent-card' : kind === 'mcp' ? 'mcp' : kind === 'rules' ? 'rules' : kind, path: file });
  if (flags.json) { console.log(JSON.stringify({ created: file, kind, verdict: g.verdict }, null, 2)); return; }
  console.log(`\n  ${green('✓ Created')} ${bold(file)} ${dim(`(${kind})`)}`);
  console.log(`  ${g.verdict === 'ALLOW' ? green('✓ gate: clean') : yellow('gate: ' + g.verdict)} ${dim('- secure-by-default template. Edit, then')} ${bold('shomra gate ' + file)}${dim('.')}\n`);
}
