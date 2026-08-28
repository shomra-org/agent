import path from 'node:path';
import { SELF_PATH } from '../agents/hook-command.mjs';
import { VERSION } from '../core/version.mjs';
import { MCP_TOOLS, mcpToolInvocation } from './server-tools.mjs';

const PROTOCOL_VERSION = '2024-11-05';
const METHOD_NOT_FOUND = -32601;
const INTERNAL_ERROR = -32603;
const MAX_OUTPUT_BYTES = 64 * 1024 * 1024;

function makeCliRunner(execFileSync, cwd) {
  return function runCli(args, stdin) {
    let stdout;
    try {
      stdout = execFileSync(process.execPath, [SELF_PATH, ...args, '--json'], {
        encoding: 'utf8',
        cwd,
        maxBuffer: MAX_OUTPUT_BYTES,
        ...(stdin != null ? { input: stdin } : { stdio: ['ignore', 'pipe', 'pipe'] }),
      });
    } catch (error) {
      stdout = error.stdout ? String(error.stdout) : '';
      if (!stdout) return { text: String(error.stderr || error.message || 'command failed') };
    }
    try {
      return { data: JSON.parse(stdout) };
    } catch {
      return { text: stdout };
    }
  };
}

function callTool(runCli, name, toolArguments) {
  const invocation = mcpToolInvocation(name, toolArguments);
  if (invocation.error) return { text: invocation.error, isError: true };
  return runCli(invocation.args, invocation.stdin);
}

function toolCallResult(result) {
  const text = result.data !== undefined
    ? JSON.stringify(result.data, null, 2)
    : String(result.text != null ? result.text : '');
  return { content: [{ type: 'text', text }], isError: !!result.isError };
}

function makeTransport() {
  const send = (message) => process.stdout.write(`${JSON.stringify(message)}\n`);
  return {
    ok: (id, result) => send({ jsonrpc: '2.0', id, result }),
    fail: (id, code, message) => send({ jsonrpc: '2.0', id, error: { code, message } }),
  };
}

function handleRequest({ id, method, params }, { transport, runCli }) {
  if (method === 'initialize') {
    return transport.ok(id, {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: { tools: {} },
      serverInfo: { name: 'shomra', version: VERSION },
    });
  }
  if (method === 'ping') return transport.ok(id, {});
  if (method === 'tools/list') return transport.ok(id, { tools: MCP_TOOLS });
  if (method === 'tools/call') {
    const result = callTool(runCli, params && params.name, params && params.arguments);
    return transport.ok(id, toolCallResult(result));
  }
  if (typeof method === 'string' && method.startsWith('notifications/')) return undefined;
  if (id !== undefined) return transport.fail(id, METHOD_NOT_FOUND, `Method not found: ${method}`);
  return undefined;
}

function parseRequest(line) {
  const trimmed = line.trim();
  if (!trimmed) return null;
  try {
    return JSON.parse(trimmed);
  } catch {
    return null;
  }
}

export async function runMcpServer(flags) {
  const { createInterface } = await import('node:readline');
  const { execFileSync } = await import('node:child_process');

  const cwd = flags.path ? path.resolve(String(flags.path)) : process.cwd();
  const runCli = makeCliRunner(execFileSync, cwd);
  const transport = makeTransport();

  const reader = createInterface({ input: process.stdin });
  reader.on('line', (line) => {
    const request = parseRequest(line);
    if (!request) return;
    try {
      handleRequest(request, { transport, runCli });
    } catch (error) {
      if (request.id !== undefined) transport.fail(request.id, INTERNAL_ERROR, String(error?.message || error));
    }
  });
  await new Promise((resolve) => reader.on('close', resolve));
}
