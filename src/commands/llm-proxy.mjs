import os from 'node:os';
import { loadConfig, resolveSettings } from '../core/config.mjs';
import { exitNotConfigured } from '../core/exit-codes.mjs';
import { bold, cyan, dim, green, red, yellow } from '../core/terminal.mjs';
import { VERSION } from '../core/version.mjs';
import { resolveAgentIdentityHandle } from './agent-identity.mjs';

export const LLM_PROVIDERS = ['openai', 'anthropic', 'gemini', 'groq', 'mistral', 'xai', 'deepseek', 'openrouter', 'together'];

const OPENAI_COMPATIBLE = ['groq', 'mistral', 'xai', 'deepseek', 'openrouter', 'together'];
const DEFAULT_PORT = 4141;
const BODYLESS_METHODS = ['GET', 'HEAD'];
const HOP_BY_HOP_REQUEST_HEADERS = ['host', 'connection', 'content-length', 'accept-encoding', 'expect'];
const HOP_BY_HOP_RESPONSE_HEADERS = ['content-length', 'transfer-encoding', 'content-encoding', 'connection'];

function newSessionId() {
  return `proxy-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

function forwardHeaders(incoming, { apiKey, actor, machineId, sessionId, project, agentId }) {
  const headers = { ...incoming };
  for (const name of HOP_BY_HOP_REQUEST_HEADERS) delete headers[name];

  headers['x-shomra-key'] = apiKey;
  headers['x-shomra-actor'] = actor;
  if (machineId) headers['x-shomra-machine'] = machineId;
  headers['x-shomra-source'] = 'shomra llm-proxy';
  if (!headers['x-shomra-session']) headers['x-shomra-session'] = sessionId;
  if (project) headers['x-shomra-project'] = project;
  if (agentId && !headers['x-shomra-agent']) headers['x-shomra-agent'] = agentId;
  return headers;
}

async function readBody(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return Buffer.concat(chunks);
}

function sendJson(response, status, payload) {
  response.writeHead(status, { 'content-type': 'application/json' });
  response.end(JSON.stringify(payload));
}

async function streamUpstreamBody(upstream, response) {
  try {
    if (upstream.body) for await (const chunk of upstream.body) response.write(chunk);
  } catch {
    return;
  }
}

async function relayResponse(upstream, response) {
  const headers = {};
  for (const [name, value] of upstream.headers) {
    if (!HOP_BY_HOP_RESPONSE_HEADERS.includes(name)) headers[name] = value;
  }
  response.writeHead(upstream.status, headers);
  await streamUpstreamBody(upstream, response);
  response.end();
}

function statusMark(status) {
  if (status === 403) return red('BLOCKED');
  return status >= 400 ? yellow(String(status)) : green(String(status));
}

function logCall(provider, request, suffix, status) {
  const time = new Date().toTimeString().slice(0, 8);
  console.log(`  ${dim(time)} ${bold(provider.padEnd(10))} ${dim(request.method)} ${suffix} ${statusMark(status)}`);
}

function createProxyHandler({ url, headerContext, providerPattern }) {
  return async (request, response) => {
    const requestPath = String(request.url).replace(/^\/llm(?=\/)/, '');
    const match = requestPath.match(providerPattern);
    if (!match) {
      sendJson(response, 404, {
        error: { message: `Unknown route - use /<provider>/… (providers: ${LLM_PROVIDERS.join(', ')})` },
      });
      return;
    }

    const [, provider, suffix] = match;
    const route = `/llm/${provider}${suffix ?? '/'}`;
    const body = await readBody(request);
    const headers = forwardHeaders(request.headers, headerContext);

    let upstream;
    try {
      upstream = await fetch(`${url}${route}`, {
        method: request.method,
        headers,
        body: BODYLESS_METHODS.includes(request.method) ? undefined : body,
      });
    } catch (error) {
      const cause = error.cause ? ` (${error.cause.code ?? ''} ${error.cause.message ?? error.cause})` : '';
      sendJson(response, 502, { error: { message: `Shomra backend unreachable at ${url}: ${error.message}${cause}` } });
      console.log(`  ${red('✗')} ${request.method} ${request.url} ${red('backend unreachable')}${dim(cause)} ${dim(`hdrs: ${Object.keys(headers).join(',')}`)}`);
      return;
    }

    await relayResponse(upstream, response);
    logCall(provider, request, suffix ?? '/', upstream.status);
  };
}

function printStartupBanner({ port, url, project, actor }) {
  console.log(bold(cyan('\n  Shomra LLM Guard')) + dim(` - local proxy v${VERSION}`));
  console.log(`  ${green('●')} Listening on ${bold(`http://127.0.0.1:${port}`)} ${dim(`→ ${url} → provider`)}`);
  if (project) console.log(`  ${dim('Project  ')} ${project}`);
  console.log(`  ${dim('Actor    ')} ${actor}\n`);

  console.log(bold('  Route your SDKs through the guard (no code changes):'));
  console.log(dim('    OpenAI / Anthropic (PowerShell)'));
  console.log(`      $env:OPENAI_BASE_URL    = "http://127.0.0.1:${port}/openai/v1"`);
  console.log(`      $env:ANTHROPIC_BASE_URL = "http://127.0.0.1:${port}/anthropic"`);
  console.log(dim('    OpenAI / Anthropic (bash/zsh)'));
  console.log(`      export OPENAI_BASE_URL=http://127.0.0.1:${port}/openai/v1`);
  console.log(`      export ANTHROPIC_BASE_URL=http://127.0.0.1:${port}/anthropic`);
  console.log(dim('    Gemini - point the Google GenAI SDK base URL at'));
  console.log(`      http://127.0.0.1:${port}/gemini`);
  console.log(dim(`    OpenAI-compatible (${OPENAI_COMPATIBLE.join(', ')}) - set the SDK baseURL to`));
  console.log(`      http://127.0.0.1:${port}/<provider>/v1`);
  console.log(dim('\n  Prompts and completions are screened against org policy;'));
  console.log(dim('  blocked calls return HTTP 403 with the reason. Ctrl+C to stop.\n'));
}

export async function cmdLlmProxy(flags) {
  const config = loadConfig();
  const { apiKey, url } = resolveSettings(config);
  if (!apiKey) exitNotConfigured();

  const port = parseInt(flags.port, 10) || DEFAULT_PORT;
  const project = flags.project ? String(flags.project) : null;
  const actor = `${os.hostname()}/${os.userInfo().username}`;

  const handler = createProxyHandler({
    url,
    providerPattern: new RegExp(`^/(${LLM_PROVIDERS.join('|')})(/.*)?$`),
    headerContext: {
      apiKey,
      actor,
      project,
      machineId: config.machineId,
      sessionId: newSessionId(),
      agentId: resolveAgentIdentityHandle(flags),
    },
  });

  const { createServer } = await import('node:http');
  createServer(handler).listen(port, '127.0.0.1', () => printStartupBanner({ port, url, project, actor }));
}
