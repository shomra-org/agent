import { gateMachine } from '../core/api-client.mjs';
import { breakerReset, breakerTrip, guardTimeoutMs } from '../core/circuit-breaker.mjs';
import { detectEnv } from '../gate/environment.mjs';

const LISTING_REPORT_TIMEOUT_MS = 2000;

async function postJson(url, apiKey, body, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Shomra-Key': apiKey, Connection: 'close' },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }
}

export async function requestConnectVerdict({ url, apiKey, server, agent, projectId }) {
  try {
    const response = await postJson(`${url}/gate/mcp-connect`, apiKey, {
      server,
      machine: gateMachine(),
      env: detectEnv(),
      agent,
      projectId,
      sessionId: process.env.SHOMRA_SESSION_ID || undefined,
    }, guardTimeoutMs());
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const verdict = await response.json();
    breakerReset();
    return { verdict };
  } catch (error) {
    breakerTrip();
    return { error };
  }
}

export function reportListing(url, apiKey, body) {
  if (!url || !apiKey) return;
  postJson(`${url}/gate/mcp-listing`, apiKey, body, LISTING_REPORT_TIMEOUT_MS).catch(() => {});
}
