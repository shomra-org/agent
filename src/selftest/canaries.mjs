import fs from 'node:fs';
import path from 'node:path';

/**
 *  THE CANARIES, IN EACH VENDOR'S REAL WIRE SHAPE.
 *
 * A self-test that called `normalizeGuardInput` itself would prove that this
 * process can screen a payload, which nobody doubted. These payloads are the
 * ones the VENDOR posts on its stdin, so what is under test is the install: the
 * matcher that decides the hook runs, the normaliser that unwraps the shape, the
 * classifier that decides to escalate, the reconstruction that builds the
 * post-edit file, and the server that answers.
 *
 * ⚠ INERT BY CONSTRUCTION. Nothing here is ever executed - the hook only reads
 * stdin and answers. The commands name a package that does not exist
 * (`shomra-selftest-canary-…`), the writes land in a throwaway directory, and
 * the whole directory is removed afterwards. The marker is NONCE-BOUND and
 * appears in the command, path or content of every canary: it is what lets the
 * server tell a self-test apart from a real `npm install evil`.
 */

export const CANARY_PREFIX = 'shomra-selftest-canary';

export const canaryPackage = (marker) => marker;

/** The throwaway working directory one self-test session uses, with its files already on disk. */
export function prepareCanaryDir(root, marker) {
  const dir = path.join(root, marker);
  fs.mkdirSync(dir, { recursive: true });
  const pkg = path.join(dir, 'package.json');
  fs.writeFileSync(pkg, `{\n  "name": "${marker}",\n  "private": true,\n  "dependencies": {\n  }\n}\n`);
  const docker = path.join(dir, 'Dockerfile');
  fs.writeFileSync(docker, `# ${marker}\nFROM node:20\nUSER node\nCMD ["node", "index.js"]\n`);
  return { dir, pkg, docker };
}

const posix = (p) => String(p).split(path.sep).join('/');

/**
 * What each canary is FOR - the sentence a porous result has to be read against.
 * ⚠ `post` marks the canaries whose whole point is the post-edit rebuild: an
 * Edit carries the replaced lines, and a subject rule handed those grades what
 * the fragment lacks as a fact about the file.
 */
export const CANARY_KINDS = {
  'shell-install': { title: 'shell install', tool: 'shell' },
  'powershell-install': { title: 'PowerShell install', tool: 'shell' },
  'write-dockerfile': { title: 'write a Dockerfile (USER root)', tool: 'write' },
  'edit-manifest': { title: 'edit package.json (adds a dependency)', tool: 'edit', post: true },
  'apply-patch': { title: 'apply_patch a Dockerfile', tool: 'patch', post: true },
  'mcp-exec': { title: 'MCP tool that runs a command', tool: 'mcp' },
  /** ⚠ An MCP server is WIRED UP through the shell on every vendor - `claude mcp add …` - so this canary is a shell call that must escalate as an MCP install. */
  'mcp-connect': { title: 'wire up an MCP server', tool: 'shell' },
};

function dockerfileText(marker) {
  return `# ${marker}\nFROM node:20\nUSER root\nRUN npm install ${marker}\n`;
}

/**
 * ⚠ THE PATCH NAMES ITS FILE INSIDE THE CANARY DIRECTORY, and the call declares
 * the PARENT as its cwd. A patch of a bare `Dockerfile` would be a canary the
 * server could only recognise by trusting a relative name, which is exactly the
 * shape a real patch of a real Dockerfile has.
 */
function patchText(rel) {
  return `*** Begin Patch\n*** Update File: ${rel}\n@@\n-USER node\n+USER root\n*** End Patch`;
}

const depEdit = (marker) => ({
  old: '"dependencies": {',
  new: `"dependencies": {\n    "${marker}": "^1.0.0",`,
});

/**
 * Every canary for one vendor, in that vendor's own payload shape.
 * ⚠ A vendor only gets the canaries it can actually carry: Cursor has no
 * pre-edit hook at all, so sending it one would manufacture a failure the
 * install cannot fix.
 */
export function canariesFor(vendor, { marker, dir, pkg, docker, session = `selftest-${marker}` }) {
  const cwd = posix(dir);
  const pkgPath = posix(pkg);
  const dockerPath = posix(docker);
  const parentCwd = posix(path.dirname(dir));
  const relDocker = `${path.basename(dir)}/Dockerfile`;
  const install = `npm install ${canaryPackage(marker)}`;
  const psInstall = `npm.cmd install ${canaryPackage(marker)}`;
  const connect = `claude mcp add ${marker} -- npx -y ${marker}`;
  const edit = depEdit(marker);
  const mcpTool = `mcp__${marker.replace(/-/g, '_')}__execute_command`;

  const make = (id, payload) => ({ id, ...CANARY_KINDS[id], payload });

  switch (vendor) {
    case 'claude':
      return [
        make('shell-install', { hook_event_name: 'PreToolUse', session_id: session, cwd, tool_name: 'Bash', tool_input: { command: install } }),
        ...(process.platform === 'win32'
          ? [make('powershell-install', { hook_event_name: 'PreToolUse', session_id: session, cwd, tool_name: 'PowerShell', tool_input: { command: psInstall } })]
          : []),
        make('write-dockerfile', { hook_event_name: 'PreToolUse', session_id: session, cwd, tool_name: 'Write', tool_input: { file_path: dockerPath, content: dockerfileText(marker) } }),
        make('edit-manifest', { hook_event_name: 'PreToolUse', session_id: session, cwd, tool_name: 'Edit', tool_input: { file_path: pkgPath, old_string: edit.old, new_string: edit.new } }),
        make('mcp-exec', { hook_event_name: 'PreToolUse', session_id: session, cwd, tool_name: mcpTool, tool_input: { command: install } }),
        make('mcp-connect', { hook_event_name: 'PreToolUse', session_id: session, cwd, tool_name: 'Bash', tool_input: { command: connect } }),
      ];

    case 'codex':
      return [
        make('shell-install', { hook_event_name: 'PreToolUse', session_id: session, cwd, tool_name: 'local_shell', tool_input: { command: ['bash', '-lc', install] } }),
        make('write-dockerfile', { hook_event_name: 'PreToolUse', session_id: session, cwd, tool_name: 'Write', tool_input: { file_path: dockerPath, content: dockerfileText(marker) } }),
        make('edit-manifest', { hook_event_name: 'PreToolUse', session_id: session, cwd, tool_name: 'Edit', tool_input: { file_path: pkgPath, old_string: edit.old, new_string: edit.new } }),
        make('apply-patch', { hook_event_name: 'PreToolUse', session_id: session, cwd: parentCwd, tool_name: 'apply_patch', tool_input: { input: patchText(relDocker) } }),
        make('mcp-exec', { hook_event_name: 'PreToolUse', session_id: session, cwd, tool_name: mcpTool, tool_input: { command: install } }),
        make('mcp-connect', { hook_event_name: 'PreToolUse', session_id: session, cwd, tool_name: 'shell', tool_input: { command: ['bash', '-lc', connect] } }),
      ];

    case 'gemini':
      return [
        make('shell-install', { hook_event_name: 'BeforeTool', session_id: session, cwd, tool_name: 'run_shell_command', tool_input: { command: install } }),
        make('write-dockerfile', { hook_event_name: 'BeforeTool', session_id: session, cwd, tool_name: 'write_file', tool_input: { file_path: dockerPath, content: dockerfileText(marker) } }),
        make('edit-manifest', { hook_event_name: 'BeforeTool', session_id: session, cwd, tool_name: 'replace', tool_input: { file_path: pkgPath, old_string: edit.old, new_string: edit.new } }),
        make('mcp-exec', { hook_event_name: 'BeforeTool', session_id: session, cwd, tool_name: mcpTool, tool_input: { command: install } }),
        make('mcp-connect', { hook_event_name: 'BeforeTool', session_id: session, cwd, tool_name: 'run_shell_command', tool_input: { command: connect } }),
      ];

    case 'cline':
      return [
        make('shell-install', { tool_name: 'execute_command', tool_input: { command: install }, cwd, task_id: session }),
        make('write-dockerfile', { tool_name: 'write_to_file', tool_input: { path: dockerPath, content: dockerfileText(marker) }, cwd, task_id: session }),
        make('edit-manifest', {
          tool_name: 'replace_in_file',
          tool_input: { path: pkgPath, diff: `------- SEARCH\n${edit.old}\n=======\n${edit.new}\n+++++++ REPLACE` },
          cwd,
          task_id: session,
        }),
        make('mcp-exec', { tool_name: 'use_mcp_tool', server_name: marker, tool_input: { server_name: marker, tool_name: 'execute_command', arguments: { command: install } }, cwd, task_id: session }),
        make('mcp-connect', { tool_name: 'execute_command', tool_input: { command: connect }, cwd, task_id: session }),
      ];

    case 'cursor':
      return [
        make('shell-install', { hook_event_name: 'beforeShellExecution', conversation_id: session, command: install, cwd, workspace_roots: [cwd] }),
        make('mcp-exec', {
          hook_event_name: 'beforeMCPExecution',
          conversation_id: session,
          server_name: marker,
          tool_name: 'execute_command',
          tool_input: { command: install },
          command: `npx -y ${marker}`,
          cwd,
        }),
        make('mcp-connect', { hook_event_name: 'beforeShellExecution', conversation_id: session, command: connect, cwd, workspace_roots: [cwd] }),
      ];

    case 'windsurf':
      return [
        make('shell-install', { agent_action_name: 'pre_run_command', trajectory_id: session, tool_info: { command_line: install, cwd } }),
        make('edit-manifest', {
          agent_action_name: 'pre_write_code',
          trajectory_id: session,
          tool_info: { file_path: pkgPath, edits: [{ old_string: edit.old, new_string: edit.new }], cwd },
        }),
        make('mcp-exec', {
          agent_action_name: 'pre_mcp_tool_use',
          trajectory_id: session,
          tool_info: { server_name: marker, tool_name: 'execute_command', tool_input: { command: install }, cwd },
        }),
        make('mcp-connect', { agent_action_name: 'pre_run_command', trajectory_id: session, tool_info: { command_line: connect, cwd } }),
      ];

    case 'copilot':
      return [
        make('shell-install', { toolName: 'bash', toolArgs: JSON.stringify({ command: install }), cwd, sessionId: session }),
        make('write-dockerfile', { toolName: 'create', toolArgs: JSON.stringify({ path: dockerPath, content: dockerfileText(marker) }), cwd, sessionId: session }),
        make('edit-manifest', { toolName: 'edit', toolArgs: JSON.stringify({ filePath: pkgPath, oldString: edit.old, newString: edit.new }), cwd, sessionId: session }),
        make('mcp-exec', { toolName: mcpTool, toolArgs: JSON.stringify({ command: install }), cwd, sessionId: session }),
        make('mcp-connect', { toolName: 'bash', toolArgs: JSON.stringify({ command: connect }), cwd, sessionId: session }),
      ];

    default:
      return [];
  }
}
