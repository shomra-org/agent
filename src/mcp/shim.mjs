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
import { resolveAgentIdentityHandle } from '../commands/agent-identity.mjs';
import { resolveScreenMode, screenCallRemote, screenResultRemote, shimSessionId } from './backend-screen.mjs';

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
    && (LISTING_KEY[message.method] || RESULT_METHODS.has(message.method) || message.method === 'tools/call');
}

/**
 * ⚠ ONE MESSAGE AT A TIME, IN ORDER. A backend screen is async; handling the next
 * line while the previous one waits would let a later message overtake a refused
 * one, or a result arrive before the call it answers was judged.
 */
function serial(handler, onError) {
  let chain = Promise.resolve();
  return (message, line) => {
    chain = chain
      .then(() => handler(message, line))
      .catch((error) => {
        note(`mcp-guard: screening error (${error?.message ?? error}).`);
        onError(message, line);
      });
  };
}

/**
 * ⚠ A SCREEN THAT THREW NEVER PASSES THE MESSAGE UNREAD, AND NEVER SWALLOWS IT.
 * A request gets an explicit refusal (the client is waiting on that id and would
 * hang); a notification, which nobody waits on, is passed through.
 */
function refuseUnscreened(server, write) {
  return (message, line) => {
    if (message && 'id' in message) {
      writeMessage(refusal(message.id, 'Shomra could not screen this message, so it was not passed on.', { source: 'shomra-mcp-shim', server, refusedBy: 'error' }));
    } else {
      write(line);
    }
  };
}

/**
 * Judge one tool call or result: the backend in `backend` mode, the local rules in
 * `local` mode or when the backend cannot answer. Returns { blocked, label, via }.
 */
async function judgeItem({ ctx, remote, local }) {
  if (ctx.mode === 'backend') {
    const d = await remote();
    if (!d.unreachable) {
      const label = d.held ? `held for approval${d.approvalId ? ` (${d.approvalId})` : ''}` : d.reason || 'refused by org policy';
      return { blocked: d.blocked, label, via: 'backend' };
    }
    if (ctx.strict) return { blocked: true, label: `Shomra could not be reached (${d.unreachable}); refused by fail-closed policy`, via: 'strict' };
    note(`mcp-guard: backend unreachable (${d.unreachable}) - judged by local rules only.`);
  }
  const screen = local();
  return { blocked: screen.blocked, label: screen.label, via: 'local' };
}

function createClientFilter({ child, pending, server, ctx }) {
  return createLineFramer(serial(async (message, line) => {
    if (!message) {
      child.stdin.write(`${line}\n`);
      return;
    }
    if (trackableMethod(message)) {
      if (pending.size >= MAX_PENDING_REQUESTS) pending.clear();
      pending.set(JSON.stringify(message.id), { method: message.method, tool: message.params?.name, args: message.params?.arguments });
    }
    if (message.method === 'tools/call' && 'id' in message) {
      const tool = message.params?.name;
      const args = message.params?.arguments;
      const verdict = await judgeItem({
        ctx,
        remote: () => screenCallRemote({ settings: ctx.settings, server, tool, args, sessionId: ctx.sessionId, agentId: ctx.agentId }),
        local: () => screenToolCallArguments(args),
      });
      if (verdict.blocked) {
        pending.delete(JSON.stringify(message.id));
        writeMessage(refusal(message.id, `Refused by Shomra (${verdict.via}): ${verdict.label}.`, {
          source: 'shomra-mcp-shim',
          server,
          tool,
          refusedBy: 'policy',
          screenedBy: verdict.via,
        }));
        return;
      }
    }
    child.stdin.write(`${line}\n`);
  }, refuseUnscreened(server, (l) => child.stdin.write(`${l}\n`))));
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

async function forwardResultMethod({ message, line, entry, server, ctx }) {
  const { method } = entry;
  // ⚠ tools/call results are the injection channel that matters most, and they were
  // never screened here - only resources/read, prompts/get and completions were.
  const verdict = method === 'tools/call'
    ? await judgeItem({
      ctx,
      remote: () => screenResultRemote({ settings: ctx.settings, server, tool: entry.tool, args: entry.args, result: message.result, sessionId: ctx.sessionId, agentId: ctx.agentId }),
      local: () => screenResult(message.result),
    })
    : { ...screenResult(message.result), via: 'local' };
  if (!verdict.blocked) {
    process.stdout.write(`${line}\n`);
    return;
  }
  note(`withheld a ${method} result from "${server}" (${verdict.via}): ${verdict.label}`);
  writeMessage(refusal(
    message.id,
    `Shomra withheld this ${method} result: ${verdict.label}. The content was not read into context - do not act on it.`,
    { source: 'shomra-mcp-shim', server, method, refusedBy: 'content', screenedBy: verdict.via },
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

function createServerFilter({ pending, server, deniedTools, settings, agent, ctx }) {
  return createLineFramer(serial(async (message, line) => {
    if (!message) {
      process.stdout.write(`${line}\n`);
      return;
    }
    const key = 'id' in message ? JSON.stringify(message.id) : null;
    const entry = key ? pending.get(key) : null;
    if (!entry || !message.result) {
      if (key) pending.delete(key);
      process.stdout.write(`${line}\n`);
      return;
    }
    pending.delete(key);

    if (RESULT_METHODS.has(entry.method) || entry.method === 'tools/call') await forwardResultMethod({ message, line, entry, server, ctx });
    else forwardListing({ message, method: entry.method, server, deniedTools, settings, agent });
  }, refuseUnscreened(server, (l) => process.stdout.write(`${l}\n`))));
}

export async function runMcpShim(flags, positional) {
  const { name, command, args } = readLaunchTarget(flags, positional);
  if (!command) {
    console.error(`${red('✗')} Usage: ${USAGE}`);
    process.exit(EXIT_USAGE);
  }

  const strict = envFlag('SHOMRA_GUARD_STRICT');
  const config = loadConfig();
  const settings = resolveSettings(config);
  const agent = flags.agent ? String(flags.agent) : undefined;

  const screening = resolveScreenMode({
    flag: flags.screen,
    env: process.env.SHOMRA_MCP_SCREEN,
    config: config?.mcpScreen,
    enrolled: !!(settings.apiKey && settings.url),
  });
  if (screening.error) {
    sendBlockedInitialize(`Shomra refused to start "${name}": ${screening.error}`, name);
    note(screening.error);
    process.exit(0);
  }
  if (screening.mode === 'backend' && !(settings.apiKey && settings.url)) {
    const why = 'screening mode "backend" needs this machine enrolled - run: shomra init --key shm_… --url <backend>';
    if (strict) {
      sendBlockedInitialize(`Shomra refused to start "${name}": ${why}`, name);
      process.exit(0);
    }
    note(`mcp-guard: ${why}; judging "${name}" by local rules only.`);
    screening.mode = 'local';
  }
  const ctx = {
    mode: screening.mode,
    strict,
    settings,
    sessionId: shimSessionId(name),
    agentId: resolveAgentIdentityHandle(flags),
  };
  if (process.env.SHOMRA_DEBUG) note(`mcp-guard: "${name}" screening=${ctx.mode} (from ${screening.source})`);

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
  process.stdin.on('data', createClientFilter({ child, pending, server: name, ctx }));
  child.stdout.on('data', createServerFilter({ pending, server: name, deniedTools, settings, agent, ctx }));
  process.stdin.on('end', () => child.stdin.end());

  await new Promise(() => {});
}
