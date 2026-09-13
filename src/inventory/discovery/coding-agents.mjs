import path from 'node:path';
import { canonicalGrant, readVendorPosture } from '../agent-posture.mjs';
import { projectRoots } from '../project-roots.mjs';
import { readEnvRedirects } from '../env-redirect.mjs';
import { exists, readText } from './fs-read.mjs';
import { HOME, PLAT, vscodeUserDir } from './platform.mjs';
import { execFileSync } from 'node:child_process';

export function listProcesses() {
  try {
    if (PLAT === 'win32') {
      const out = execFileSync('tasklist', ['/fo', 'csv', '/nh'], { timeout: 4000, encoding: 'utf8', windowsHide: true, maxBuffer: 16 * 1024 * 1024 });
      return out.split(/\r?\n/).map((l) => (l.match(/^"([^"]+)"/)?.[1] || '').toLowerCase()).filter(Boolean);
    }
    const out = execFileSync('ps', ['-eo', 'comm='], { timeout: 4000, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
    return out.split(/\r?\n/).map((s) => s.trim().toLowerCase()).filter(Boolean);
  } catch {
    return [];
  }
}

export function discoverCodingAgents(roots = [process.cwd()]) {
  const cwd = process.cwd();
  const agents = [
    { vendor: 'claude-code', name: 'Claude Code', probes: [path.join(HOME, '.claude.json'), path.join(HOME, '.claude')], hookFiles: [path.join(HOME, '.claude', 'settings.json'), path.join(cwd, '.claude', 'settings.json')] },
    { vendor: 'cursor', name: 'Cursor', probes: [path.join(HOME, '.cursor')], hookFiles: [path.join(HOME, '.cursor', 'hooks.json'), path.join(cwd, '.cursor', 'hooks.json')] },
    { vendor: 'windsurf', name: 'Windsurf', probes: [path.join(HOME, '.codeium', 'windsurf')], hookFiles: [path.join(HOME, '.codeium', 'windsurf', 'hooks.json'), path.join(cwd, '.windsurf', 'hooks.json')] },
    { vendor: 'gemini', name: 'Gemini CLI', probes: [path.join(HOME, '.gemini')], hookFiles: [path.join(HOME, '.gemini', 'settings.json'), path.join(cwd, '.gemini', 'settings.json')] },
    { vendor: 'codex', name: 'OpenAI Codex CLI', probes: [path.join(HOME, '.codex')], hookFiles: [path.join(HOME, '.codex', 'hooks.json'), path.join(cwd, '.codex', 'hooks.json')] },
    { vendor: 'copilot', name: 'GitHub Copilot', probes: [path.join(HOME, '.copilot'), path.join(vscodeUserDir(), 'globalStorage', 'github.copilot-chat')], hookFiles: [path.join(HOME, '.copilot', 'hooks', 'shomra.json'), path.join(cwd, '.github', 'hooks', 'shomra.json')] },
    { vendor: 'qwen-code', name: 'Qwen Code', probes: [path.join(HOME, '.qwen')], hookFiles: [path.join(HOME, '.qwen', 'settings.json'), path.join(cwd, '.qwen', 'settings.json')] },
    { vendor: 'kiro', name: 'Kiro', probes: [path.join(HOME, '.kiro'), path.join(HOME, '.aws', 'amazonq')], hookFiles: [] },
    { vendor: 'opencode', name: 'OpenCode', probes: [path.join(HOME, '.config', 'opencode'), path.join(HOME, '.local', 'share', 'opencode')], hookFiles: [] },
    { vendor: 'goose', name: 'Goose', probes: [path.join(HOME, '.config', 'goose'), path.join(process.env.APPDATA || path.join(HOME, 'AppData', 'Roaming'), 'Block', 'goose')], hookFiles: [] },
    { vendor: 'zed', name: 'Zed', probes: [path.join(HOME, '.config', 'zed'), path.join(process.env.APPDATA || path.join(HOME, 'AppData', 'Roaming'), 'Zed')], hookFiles: [] },
    { vendor: 'augment', name: 'Augment', probes: [path.join(HOME, '.augment')], hookFiles: [] },
    { vendor: 'continue', name: 'Continue', probes: [path.join(HOME, '.continue')], hookFiles: [] },
    { vendor: 'amp', name: 'Amp', probes: [path.join(HOME, '.config', 'amp'), path.join(vscodeUserDir(), 'globalStorage', 'sourcegraph.amp')], hookFiles: [] },
    { vendor: 'cline', name: 'Cline', probes: [...['Code', 'Cursor', 'Windsurf'].map((app) => path.join(vscodeUserDir(app), 'globalStorage', 'saoudrizwan.claude-dev')), path.join(HOME, '.cline', 'data')], hookFiles: [path.join(HOME, '.cline', 'hooks.json'), path.join(cwd, '.cline', 'hooks.json')] },
    { vendor: 'roo', name: 'Roo Code', probes: ['Code', 'Cursor', 'Windsurf'].map((app) => path.join(vscodeUserDir(app), 'globalStorage', 'rooveterinaryinc.roo-cline')), hookFiles: [path.join(cwd, '.roo', 'hooks.json')] },
    { vendor: 'aider', name: 'Aider', probes: [path.join(HOME, '.aider.conf.yml'), path.join(cwd, '.aider.conf.yml'), path.join(HOME, '.aider')], hookFiles: [path.join(HOME, '.aider.conf.yml'), path.join(cwd, '.aider.conf.yml')] },
  ];
  const assets = [];
  let projects = null;
  for (const a of agents) {
    const installedAt = a.probes.find((p) => exists(p));
    if (!installedAt) continue;
    const guardFile = a.hookFiles.find((f) => {
      const t = readText(f, 20_000);
      return t != null && /shomra/i.test(t);
    });

    projects ??= projectRoots(cwd, roots);
    const posture = readVendorPosture(a.vendor, cwd, projects);
    const grant = canonicalGrant(posture);
    assets.push({
      type: 'AI_AGENT',
      name: a.name,
      identifier: `agent:${a.vendor}`,
      vendor: a.vendor,
      ...(grant ? { content: grant } : {}),
      metadata: {
        detectedAt: installedAt,
        guarded: !!guardFile,
        guardFile: guardFile || null,
        envRedirects: readEnvRedirects(a.vendor, cwd),
        posture: posture
          ? {
              tier: posture.tier,
              readable: posture.readable,
              claim: posture.claim,
              mode: posture.mode,
              allowCount: posture.allow.length,
              denyCount: posture.deny.length,
              askCount: posture.ask.length,
              allow: posture.allow.slice(0, 25),
              enableAllProjectMcpServers: posture.enableAllProjectMcpServers,
              switches: posture.switches,
              mcpServerCount: posture.mcpServers.length,
              autoApprovedMcp: posture.autoApprovedMcp,
              unreadableCount: posture.unreadableCount,
              projectsScanned: posture.projectsScanned,
              projectsWithSettings: posture.projectsWithSettings,

              sources: posture.sources.map((s) => ({ path: s.path, scope: s.scope, state: s.state, reason: s.reason })),
            }
          : null,
      },
    });
  }
  return assets;
}
