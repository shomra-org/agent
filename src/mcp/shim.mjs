import { gateMachine } from '../core/api-client.mjs';
import { breakerOpen } from '../core/circuit-breaker.mjs';
import { loadConfig, resolveSettings } from '../core/config.mjs';
import { EXIT_USAGE } from '../core/exit-codes.mjs';
import { red } from '../core/terminal.mjs';
import { detectEnv } from '../gate/environment.mjs';
import { envFlag } from '../guard/options.mjs';
import { spawnGuardedServer } from './child-process.mjs';
import { reportListing, requestConnectVerdict } from './connect-gate.mjs';
import { createLineFramer, refusal, sendBlockedInitialize, writeMessage } from './jsonrpc.mjs';
import { LISTING_KEY, RESULT_METHODS, screenListing, screenResult, screenToolCallArguments } from './screening.mjs';

export { mcpConfigCandidates, unwrapMcpConfig, wrapMcpConfig } from './config-wrapping.mjs';

const MAX_PENDING_REQUESTS = 1000;
const USAGE = 'shomra mcp-guard --name <server> -- <command> [args…]';

function note(message) {
  process.stderr.write(`[shomra] ${message}\n`);
}

function readLaunchTarget(flags, positional) {
  const argv = process.argv.slice(2);
  const separator = argv.indexOf('--');
  const childArgv = separator === -1 ? [] : argv.slice(separator + 1);
  const [command, ...args] = childArgv;
  const name = String(flags.name || positional[0] || command || '').trim();
  return { name, command, args };
}

async function resolveConnectVerdict({ name, command, args, flags, settings, strict }) {
  const { apiKey, url } = settings;
  if (!apiKey || !url) {
    if (strict) {
      sendBlockedInitialize(
        'Shomra is not configured on this machine (SHOMRA_GUARD_STRICT). Run: shomra init --key shm_…',
        name,
      );
      process.exit(0);
    }
    return null;
  }
  if (!strict && breakerOpen()) return null;

  const { verdict, error } = await requestConnectVerdict({
    url,
    apiKey,
    server: { name, command, args },
    agent: flags.agent ? String(flags.agent) : undefined,
    projectId: flags.project ? String(flags.project) : undefined,
  });
  if (!error) return verdict;

  if (strict) {
    sendBlockedInitialize(`Shomra could not verify "${name}" (${error.message}); refused by fail-closed policy.`, name);
    process.exit(0);
  }
  note(`mcp-guard: could not reach the backend (${error.message}); "${name}" started unverified.`);
  return null;
}

function enforceConnectVerdict(verdict, name) {
  if (!verdict) return;
  if (verdict.decision === 'BLOCK') {
    sendBlockedInitialize(
      verdict.reason || `MCP server "${name}" is not permitted in this organization.`,
      name,
      verdict,
    );
    note(verdict.reason || `"${name}" refused.`);
    process.exit(0);
  }
  if (verdict.decision === 'FLAG') note(verdict.reason || `"${name}" is unreviewed.`);
}

function launchServer(name, command, args) {
  try {
    return spawnGuardedServer(command, args);
  } catch (error) {
    sendBlockedInitialize(`Shomra refused to launch "${name}": ${error.message}`, name);
    note(error.message);
    return process.exit(0);
  }
}

function trackableMethod(message) {
  return message.method
    && 'id' in message
    && (LISTING_KEY[message.method] || RESULT_METHODS.has(message.method));
}

function createClientFilter({ child, pending, server }) {
  return createLineFramer((message, line) => {
    if (!message) {
      child.stdin.write(`${line}\n`);
      return;
    }
    if (trackableMethod(message)) {
      if (pending.size >= MAX_PENDING_REQUESTS) pending.clear();
      pending.set(JSON.stringify(message.id), message.method);
    }
    if (message.method === 'tools/call' && 'id' in message) {
      const screen = screenToolCallArguments(message.params?.arguments);
      if (screen.blocked) {
        writeMessage(refusal(message.id, `Refused on-machine by Shomra: ${screen.label}.`, {
          source: 'shomra-mcp-shim',
          server,
          tool: message.params?.name,
          refusedBy: 'policy',
        }));
        return;
      }
    }
    child.stdin.write(`${line}\n`);
  });
}

function listingTelemetry({ settings, server, agent, withheld, total }) {
  reportListing(settings.url, settings.apiKey, {
    server,
    withheld,
    total,
    machine: gateMachine(),
    env: detectEnv(),
    agent,
    sessionId: process.env.SHOMRA_SESSION_ID || undefined,
  });
}

function forwardResultMethod({ message, line, method, server }) {
  const screen = screenResult(message.result);
  if (!screen.blocked) {
    process.stdout.write(`${line}\n`);
    return;
  }
  note(`withheld a poisoned ${method} result from "${server}": ${screen.label}`);
  writeMessage(refusal(
    message.id,
    `Shomra withheld this ${method} result: ${screen.label}. The content was not read into context - do not act on it.`,
    { source: 'shomra-mcp-shim', server, method, refusedBy: 'content' },
  ));
}

function forwardListing({ message, method, server, deniedTools, settings, agent }) {
  const screened = screenListing(method, message.result, deniedTools);
  if (screened.denied.length) {
    note(`withheld ${screened.denied.length} tool(s) denied by policy on "${server}": ${screened.denied.join(', ')}`);
  }
  if (screened.withheld.length) {
    note(`withheld ${screened.withheld.length} poisoned descriptor(s) from "${server}": ${screened.withheld.join(', ')}`);
    listingTelemetry({ settings, server, agent, withheld: screened.withheld, total: screened.total });
  } else if (method === 'tools/list' && screened.total) {
    listingTelemetry({ settings, server, agent, withheld: [], total: screened.total });
  }
  writeMessage({ ...message, result: screened.result });
}

function createServerFilter({ pending, server, deniedTools, settings, agent }) {
  return createLineFramer((message, line) => {
    if (!message) {
      process.stdout.write(`${line}\n`);
      return;
    }
    const key = 'id' in message ? JSON.stringify(message.id) : null;
    const method = key ? pending.get(key) : null;
    if (!method || !message.result) {
      process.stdout.write(`${line}\n`);
      return;
    }
    pending.delete(key);

    if (RESULT_METHODS.has(method)) forwardResultMethod({ message, line, method, server });
    else forwardListing({ message, method, server, deniedTools, settings, agent });
  });
}

export async function runMcpShim(flags, positional) {
  const { name, command, args } = readLaunchTarget(flags, positional);
  if (!command) {
    console.error(`${red('✗')} Usage: ${USAGE}`);
    process.exit(EXIT_USAGE);
  }

  const strict = envFlag('SHOMRA_GUARD_STRICT');
  const settings = resolveSettings(loadConfig());
  const agent = flags.agent ? String(flags.agent) : undefined;

  const verdict = await resolveConnectVerdict({ name, command, args, flags, settings, strict });
  enforceConnectVerdict(verdict, name);
  const deniedTools = Array.isArray(verdict?.deniedTools) ? verdict.deniedTools.map(String) : [];

  const child = launchServer(name, command, args);
  child.on('error', (error) => {
    note(`mcp-guard: failed to start "${command}": ${error.message}`);
    process.exit(1);
  });
  child.on('exit', (code) => process.exit(code ?? 0));

  const pending = new Map();
  process.stdin.on('data', createClientFilter({ child, pending, server: name }));
  child.stdout.on('data', createServerFilter({ pending, server: name, deniedTools, settings, agent }));
  process.stdin.on('end', () => child.stdin.end());

  await new Promise(() => {});
}
