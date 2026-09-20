/**
 *  ONE TABLE FOR "WHICH TOOL NAMES THIS VENDOR PUTS IN FRONT OF THE HOOK".
 *
 * The matcher decides whether the hook runs at all, and a tool it does not name
 * is never screened - not locally, not by the server (see `installers.mjs`).
 * The matcher strings, the names `classify.mjs` treats as shell / write / patch,
 * and the payload shapes `normalize.mjs` unwraps were three separate lists that
 * agreed by hand; `shomra selftest` needs the same list a fourth time to say
 * which names a settings file is MISSING. So it lives here once, and
 * `tests/selftest.test.mjs` pins it against classify/normalize.
 *
 * ⚠ `matcher` is what the installer WRITES; `required` is what must be COVERED.
 * They are not the same thing: Gemini CLI is wired match-all (`.*`), which
 * covers every required name without listing one. A vendor with no matcher at
 * all (Cursor, Windsurf, Copilot) wires one hook PER EVENT instead, and there
 * the events are the coverage: an event that is not wired is a whole class of
 * call the hook never sees.
 */

/** `mcp__.*` is a PATTERN in a matcher, so coverage is checked against a real call name. */
export const MCP_SAMPLE = 'mcp__shomra_selftest__execute_command';

const mcp = { name: 'mcp__.*', kind: 'mcp', sample: MCP_SAMPLE };

export const VENDOR_TOOLS = {
  claude: {
    label: 'Claude Code',
    settings: { file: 'settings.json', dirs: ['~/.claude', './.claude'], shape: 'claude' },
    probes: ['~/.claude', '~/.claude.json'],
    event: 'PreToolUse',
    matcher: 'Bash|PowerShell|Write|Edit|MultiEdit|NotebookEdit|mcp__.*',
    required: [
      { name: 'Bash', kind: 'shell' },
      /** ⚠ The shell on Windows. Missing here once, so every `npm install` an agent ran there reached no hook. */
      { name: 'PowerShell', kind: 'shell' },
      { name: 'Write', kind: 'write' },
      { name: 'Edit', kind: 'edit' },
      { name: 'MultiEdit', kind: 'edit' },
      { name: 'NotebookEdit', kind: 'edit' },
      mcp,
    ],
    env: (cwd) => ({ CLAUDE_PROJECT_DIR: cwd }),
  },

  codex: {
    label: 'OpenAI Codex CLI',
    settings: { file: 'hooks.json', dirs: ['~/.codex', './.codex'], shape: 'codex' },
    probes: ['~/.codex'],
    event: 'PreToolUse',
    matcher: 'Bash|shell|local_shell|exec_command|apply_patch|Write|Edit|mcp__.*',
    required: [
      { name: 'Bash', kind: 'shell' },
      { name: 'shell', kind: 'shell' },
      { name: 'local_shell', kind: 'shell' },
      { name: 'exec_command', kind: 'shell' },
      /** ⚠ Named explicitly so the matcher does not rest on the `Edit|Write` alias. */
      { name: 'apply_patch', kind: 'patch' },
      { name: 'Write', kind: 'write' },
      { name: 'Edit', kind: 'edit' },
      mcp,
    ],
    env: (cwd) => ({ CODEX_PROJECT_DIR: cwd }),
  },

  gemini: {
    label: 'Gemini CLI',
    settings: { file: 'settings.json', dirs: ['~/.gemini', './.gemini'], shape: 'gemini' },
    probes: ['~/.gemini'],
    event: 'BeforeTool',
    /** ⚠ Wired match-all on purpose - Gemini's tool names are not stable enough to enumerate in a matcher. */
    matcher: '.*',
    required: [
      { name: 'run_shell_command', kind: 'shell' },
      { name: 'write_file', kind: 'write' },
      { name: 'replace', kind: 'edit' },
      mcp,
    ],
    env: (cwd) => ({ GEMINI_PROJECT_DIR: cwd }),
  },

  cline: {
    label: 'Cline',
    settings: { file: 'hooks.json', dirs: ['~/.cline', './.cline'], shape: 'claude' },
    probes: ['~/.cline'],
    event: 'PreToolUse',
    matcher: 'execute_command|write_to_file|replace_in_file|new_rule|use_mcp_tool',
    required: [
      { name: 'execute_command', kind: 'shell' },
      { name: 'write_to_file', kind: 'write' },
      { name: 'replace_in_file', kind: 'edit' },
      { name: 'new_rule', kind: 'write' },
      { name: 'use_mcp_tool', kind: 'mcp', sample: 'use_mcp_tool' },
    ],
    env: () => ({}),
  },

  cursor: {
    label: 'Cursor',
    settings: { file: 'hooks.json', dirs: ['~/.cursor', './.cursor'], shape: 'flat-events' },
    probes: ['~/.cursor'],
    matcher: null,
    /**
     * ⚠ NO MATCHER, SO THE EVENT IS THE COVERAGE. `beforeShellExecution` and
     * `beforeMCPExecution` are the two pre-events Cursor offers; a file edit is
     * only observable AFTER it lands (`afterFileEdit`), which is a limit of the
     * vendor, not of this install - reported as a note, never as porous.
     */
    events: [
      { name: 'beforeShellExecution', kind: 'shell' },
      { name: 'beforeMCPExecution', kind: 'mcp' },
    ],
    postEvents: [{ name: 'afterFileEdit', kind: 'edit', note: 'Cursor screens a file edit only after it lands - there is no pre-edit hook to install.' }],
    required: [],
    env: () => ({}),
  },

  windsurf: {
    label: 'Windsurf',
    settings: { file: 'hooks.json', dirs: ['~/.codeium/windsurf', './.windsurf'], shape: 'flat-events' },
    probes: ['~/.codeium/windsurf'],
    matcher: null,
    events: [
      { name: 'pre_run_command', kind: 'shell' },
      { name: 'pre_write_code', kind: 'edit' },
      { name: 'pre_mcp_tool_use', kind: 'mcp' },
    ],
    postEvents: [],
    required: [],
    env: () => ({}),
  },

  copilot: {
    label: 'GitHub Copilot CLI',
    settings: { file: 'shomra.json', dirs: ['~/.copilot/hooks', './.github/hooks'], shape: 'copilot' },
    probes: ['~/.copilot'],
    matcher: null,
    events: [{ name: 'preToolUse', kind: 'all' }],
    postEvents: [],
    /** ⚠ Copilot's single pre-event carries every tool, so the names are what the SCREEN must know, not the matcher. */
    required: [
      { name: 'bash', kind: 'shell' },
      { name: 'create', kind: 'write' },
      { name: 'edit', kind: 'edit' },
      mcp,
    ],
    env: () => ({}),
  },
};

export const VENDOR_KEYS = Object.keys(VENDOR_TOOLS);

/** The matcher string the installer writes for a vendor, derived from the one table. */
export function matcherFor(vendor) {
  const v = VENDOR_TOOLS[vendor];
  if (!v || v.matcher === null) return null;
  return v.matcher === '.*' ? '.*' : v.required.map((t) => t.name).join('|');
}

/** Every tool name a vendor's matcher must cover, in matcher order. */
export function requiredToolNames(vendor) {
  return (VENDOR_TOOLS[vendor]?.required ?? []).map((t) => t.name);
}

const MATCH_ALL = new Set(['*', '.*', '.+', '']);

/**
 * Does this matcher put `name` in front of the hook? ⚠ Read as the VENDOR reads
 * it - a regex over the whole tool name - not as a list of literals: `mcp__.*`
 * covers `mcp__jira__create_issue`, and a hand-written `Bash|Power.*` covers
 * PowerShell. A matcher we cannot compile is reported as not covering, because
 * neither can the agent.
 */
export function matcherCovers(matcher, name, sample = name) {
  const m = typeof matcher === 'string' ? matcher.trim() : '';
  if (MATCH_ALL.has(m)) return true;
  const parts = m.split('|').map((s) => s.trim()).filter(Boolean);
  if (parts.includes(name)) return true;
  for (const probe of [sample, name]) {
    for (const p of parts) {
      try {
        if (new RegExp(`^(?:${p})$`).test(probe)) return true;
      } catch {
        /* an uncompilable alternative covers nothing - the agent cannot run it either */
      }
    }
  }
  return false;
}

/** The names a matcher leaves uncovered, with what each one is for. */
export function missingTools(vendor, matcher) {
  return (VENDOR_TOOLS[vendor]?.required ?? []).filter((t) => !matcherCovers(matcher, t.name, t.sample ?? t.name));
}

export const KIND_LABEL = {
  shell: 'shell commands',
  write: 'file writes',
  edit: 'file edits',
  patch: 'patches',
  mcp: 'MCP calls',
  all: 'every tool',
};
