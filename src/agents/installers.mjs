import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { readJsonFile } from '../core/json-file.mjs';
import { LLM_PROXY_BASE, hookCommand } from './hook-command.mjs';
import { hasFlatHook, hasGroupedHook } from './hook-files.mjs';

export const AGENT_LABELS = {
  claude: 'Claude Code',
  cursor: 'Cursor',
  windsurf: 'Windsurf',
  gemini: 'Gemini CLI',
  codex: 'OpenAI Codex CLI',
  copilot: 'GitHub Copilot CLI',
  cline: 'Cline',
  aider: 'Aider',
};

export const AGENT_KEYS = Object.keys(AGENT_LABELS);

export const AGENT_INSTALLERS = {
  claude(global) {
    const dir = global ? path.join(os.homedir(), '.claude') : path.join(process.cwd(), '.claude');
    const file = path.join(dir, 'settings.json');
    const settings = readJsonFile(file);
    settings.hooks = settings.hooks || {};
    const pre = (settings.hooks.PreToolUse = settings.hooks.PreToolUse || []);
    const post = (settings.hooks.PostToolUse = settings.hooks.PostToolUse || []);
    let changed = false;
    if (!hasGroupedHook(pre, 'tool-guard')) {
      pre.push({ matcher: 'Bash|Write|Edit|MultiEdit|NotebookEdit|mcp__.*', hooks: [{ type: 'command', command: hookCommand('tool-guard --agent claude') }] });
      changed = true;
    }
    if (!hasGroupedHook(post, 'result-guard')) {
      post.push({ matcher: 'WebFetch|WebSearch|Read|NotebookRead|mcp__.*', hooks: [{ type: 'command', command: hookCommand('result-guard --agent claude') }] });
      changed = true;
    }

    const prompt = (settings.hooks.UserPromptSubmit = settings.hooks.UserPromptSubmit || []);
    if (!hasGroupedHook(prompt, 'prompt-guard')) {
      prompt.push({ hooks: [{ type: 'command', command: hookCommand('prompt-guard --agent claude') }] });
      changed = true;
    }

    if (!hasGroupedHook(pre, 'plan-guard')) {
      pre.push({ matcher: 'ExitPlanMode', hooks: [{ type: 'command', command: hookCommand('plan-guard --agent claude') }] });
      changed = true;
    }
    if (changed) {
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(file, JSON.stringify(settings, null, 2));
    }
    return { file, changed };
  },

  codex(global) {
    const dir = global ? path.join(os.homedir(), '.codex') : path.join(process.cwd(), '.codex');
    const file = path.join(dir, 'hooks.json');
    const settings = readJsonFile(file);
    const pre = (settings.PreToolUse = settings.PreToolUse || []);
    const post = (settings.PostToolUse = settings.PostToolUse || []);
    let changed = false;
    if (!hasGroupedHook(pre, 'tool-guard')) {
      pre.push({ matcher: 'Bash|Write|Edit|mcp__.*', hooks: [{ type: 'command', command: hookCommand('tool-guard --agent codex') }] });
      changed = true;
    }
    if (!hasGroupedHook(post, 'result-guard')) {
      post.push({ matcher: 'WebFetch|WebSearch|Read|mcp__.*', hooks: [{ type: 'command', command: hookCommand('result-guard --agent codex') }] });
      changed = true;
    }
    if (changed) {
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(file, JSON.stringify(settings, null, 2));
    }
    return { file, changed };
  },

  gemini(global) {
    const dir = global ? path.join(os.homedir(), '.gemini') : path.join(process.cwd(), '.gemini');
    const file = path.join(dir, 'settings.json');
    const settings = readJsonFile(file);
    settings.hooks = settings.hooks || {};
    const before = (settings.hooks.BeforeTool = settings.hooks.BeforeTool || []);
    const after = (settings.hooks.AfterTool = settings.hooks.AfterTool || []);
    let changed = false;
    if (!hasGroupedHook(before, 'tool-guard')) {
      before.push({ matcher: '.*', hooks: [{ type: 'command', command: hookCommand('tool-guard --agent gemini') }] });
      changed = true;
    }
    if (!hasGroupedHook(after, 'result-guard')) {
      after.push({ matcher: '.*', hooks: [{ type: 'command', command: hookCommand('result-guard --agent gemini') }] });
      changed = true;
    }
    if (changed) {
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(file, JSON.stringify(settings, null, 2));
    }
    return { file, changed };
  },

  cursor(global) {
    const dir = global ? path.join(os.homedir(), '.cursor') : path.join(process.cwd(), '.cursor');
    const file = path.join(dir, 'hooks.json');
    const cfg = readJsonFile(file);
    if (cfg.version === undefined) cfg.version = 1;
    cfg.hooks = cfg.hooks || {};
    let changed = false;
    const wire = (event, command) => {
      const list = (cfg.hooks[event] = cfg.hooks[event] || []);
      if (!hasFlatHook(list)) {
        list.push({ command });
        changed = true;
      }
    };
    wire('beforeShellExecution', hookCommand('tool-guard --agent cursor'));
    wire('beforeMCPExecution', hookCommand('tool-guard --agent cursor'));
    wire('afterFileEdit', hookCommand('result-guard --agent cursor'));
    wire('afterMCPExecution', hookCommand('result-guard --agent cursor'));

    wire('beforeSubmitPrompt', hookCommand('prompt-guard --agent cursor'));
    if (changed) {
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(file, JSON.stringify(cfg, null, 2));
    }
    return { file, changed };
  },

  windsurf(global) {
    const dir = global ? path.join(os.homedir(), '.codeium', 'windsurf') : path.join(process.cwd(), '.windsurf');
    const file = path.join(dir, 'hooks.json');
    const cfg = readJsonFile(file);
    cfg.hooks = cfg.hooks || {};
    let changed = false;
    const wire = (event, command) => {
      const list = (cfg.hooks[event] = cfg.hooks[event] || []);
      if (!hasFlatHook(list)) {
        list.push({ command });
        changed = true;
      }
    };
    wire('pre_run_command', hookCommand('tool-guard --agent windsurf'));
    wire('pre_write_code', hookCommand('tool-guard --agent windsurf'));
    wire('pre_mcp_tool_use', hookCommand('tool-guard --agent windsurf'));
    wire('post_mcp_tool_use', hookCommand('result-guard --agent windsurf'));
    if (changed) {
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(file, JSON.stringify(cfg, null, 2));
    }
    return { file, changed };
  },

  copilot(global) {
    const dir = global ? path.join(os.homedir(), '.copilot', 'hooks') : path.join(process.cwd(), '.github', 'hooks');
    const file = path.join(dir, 'shomra.json');
    if (fs.existsSync(file)) return { file, changed: false };
    const cfg = {
      preToolUse: [{ command: hookCommand('tool-guard --agent copilot') }],
      postToolUse: [{ command: hookCommand('result-guard --agent copilot') }],
    };
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(file, JSON.stringify(cfg, null, 2));
    return { file, changed: true };
  },

  cline(global) {
    const dir = global ? path.join(os.homedir(), '.cline') : path.join(process.cwd(), '.cline');
    const file = path.join(dir, 'hooks.json');
    const settings = readJsonFile(file);
    settings.hooks = settings.hooks || {};
    const pre = (settings.hooks.PreToolUse = settings.hooks.PreToolUse || []);
    const post = (settings.hooks.PostToolUse = settings.hooks.PostToolUse || []);
    let changed = false;
    if (!hasGroupedHook(pre, 'tool-guard')) {
      pre.push({ matcher: 'execute_command|write_to_file|replace_in_file|new_rule|use_mcp_tool', hooks: [{ type: 'command', command: hookCommand('tool-guard --agent cline') }] });
      changed = true;
    }
    if (!hasGroupedHook(post, 'result-guard')) {
      post.push({ matcher: 'read_file|web_fetch|use_mcp_tool', hooks: [{ type: 'command', command: hookCommand('result-guard --agent cline') }] });
      changed = true;
    }
    if (changed) {
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(file, JSON.stringify(settings, null, 2));
    }
    return { file, changed };
  },

  aider(global) {
    const file = global ? path.join(os.homedir(), '.aider.conf.yml') : path.join(process.cwd(), '.aider.conf.yml');
    let text = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
    if (/#\s*shomra llm guard/i.test(text) || text.includes(LLM_PROXY_BASE)) {
      return { file, changed: false };
    }
    const block =
      `\n# --- shomra llm guard ---\n` +
      `# Routes Aider's model traffic through the Shomra LLM Guard proxy so every\n` +
      `# prompt/response is policy-screened. Requires: shomra llm-proxy (running).\n` +
      `openai-api-base: ${LLM_PROXY_BASE}\n` +
      `# --- end shomra ---\n`;
    fs.writeFileSync(file, (text.endsWith('\n') || !text ? text : text + '\n') + block);
    return { file, changed: true };
  },
};
