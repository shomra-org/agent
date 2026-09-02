import { loadConfig, resolveSettings } from '../core/config.mjs';
import { detectEnv, remoteRunner } from '../gate/environment.mjs';
import { envFlag, resolveAgentFlag } from './options.mjs';

const PROBE_TIMEOUT_MS = 1500;

export function sessionPosture(env, settings, reachable) {
  const remote = env.environment === 'REMOTE';
  if (!settings.apiKey) {
    return {
      enforcing: 'local-only',
      remote,
      message: remote
        ? 'This is an EPHEMERAL CLOUD SESSION and no Shomra key reached it. Nothing you installed on your laptop is here. Only the offline Tier-0 screen is running; no policy, no server-side flow taint, and nothing about this session will appear in Shomra.'
        : 'Shomra is not configured on this machine. Only the offline Tier-0 screen is running.',
    };
  }
  if (reachable === false) {
    return {
      enforcing: 'degraded',
      remote,
      message: remote
        ? 'This CLOUD SESSION cannot reach the Shomra backend - its network policy is blocking egress. Tool calls run screened by the offline tier only, and ⚠ THIS CONTAINER IS EPHEMERAL: the gap ledger dies with it, so these calls may never be reported as unscreened.'
        : 'The Shomra backend is unreachable. The offline tier still screens; server-side policy does not.',
    };
  }
  return { enforcing: 'full', remote, message: null };
}

async function reachable(url) {
  if (!url) return false;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), PROBE_TIMEOUT_MS);
  try {
    await fetch(`${url.replace(/\/+$/, '')}/healthz`, { signal: ctrl.signal, headers: { Connection: 'close' } });
    return true;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * ⚠ THE ONE THING A CLOUD SESSION CAN TELL YOU IS THAT IT STARTED. Everything
 * downstream - the tool guard, the gap ledger, the enforcement record - needs
 * egress the container may not have, and the container is reclaimed either way.
 * So this runs first, says out loud what is and is not enforcing, and never
 * blocks: a session that refuses to start is a control nobody keeps installed.
 */
export async function cmdSessionGuard(flags) {
  resolveAgentFlag(flags);
  if (envFlag('SHOMRA_SESSION_GUARD_OFF')) return process.exit(0);

  try {
    const env = detectEnv();
    const settings = resolveSettings(loadConfig());
    const posture = sessionPosture(env, settings, settings.apiKey ? await reachable(settings.url) : null);
    if (posture.message) process.stderr.write(`[shomra] ${posture.message}\n`);
  } catch {

  }
  process.exit(0);
}

export { remoteRunner };
