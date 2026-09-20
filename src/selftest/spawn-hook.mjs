import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { shomraHookRe } from '../agents/hook-command.mjs';
import { VENDOR_TOOLS } from '../agents/vendor-tools.mjs';
import { clampInt } from '../core/numbers.mjs';

/**
 *  THE INSTALLED HOOK, SPAWNED THE WAY THE VENDOR SPAWNS IT.
 *
 * Every vendor runs its hook as a COMMAND STRING through a shell, with the
 * payload on stdin. Calling `cmdToolGuard` in-process instead would skip the
 * command string in the settings file - which is the part that goes stale, names
 * a checkout that no longer exists, or resolves through an npm version nobody
 * published - and would report a healthy hook on a machine where the agent's own
 * spawn fails silently.
 *
 * ⚠ ONLY OUR OWN ENTRY IS EVER SPAWNED. The command comes out of a settings file
 * that anything on this machine can write, so it is matched against the Shomra
 * tool-guard pattern first. A self-test that executed whatever the settings file
 * said would be a local privilege escalation wearing a test's clothes.
 */

export function isShomraToolGuard(command) {
  return shomraHookRe('tool-guard').test(String(command ?? ''));
}

export function selftestTimeoutMs() {
  return clampInt(process.env.SHOMRA_SELFTEST_TIMEOUT_MS, 30_000, 1000, 300_000);
}

function readReceipts(file) {
  try {
    return fs
      .readFileSync(file, 'utf8')
      .split('\n')
      .filter((l) => l.trim())
      .map((l) => {
        try {
          return JSON.parse(l);
        } catch {
          return null;
        }
      })
      .filter(Boolean);
  } catch {
    return [];
  }
}

/**
 * Run one canary through one installed hook entry.
 * @returns {Promise<{code:number|null, stdout:string, stderr:string, ms:number, receipts:object[], spawnError:string|null}>}
 */
export function runCanary({ command, vendor, canary, payload, cwd, session, receiptDir, env = process.env }) {
  if (!isShomraToolGuard(command)) {
    return Promise.resolve({ code: null, stdout: '', stderr: '', ms: 0, receipts: [], spawnError: 'not a Shomra tool-guard hook command - refused to spawn' });
  }
  const receipt = path.join(receiptDir, `${vendor}.${canary}.jsonl`);
  const vendorEnv = VENDOR_TOOLS[vendor]?.env?.(cwd) ?? {};
  const childEnv = {
    ...env,
    ...vendorEnv,
    NO_COLOR: '1',
    SHOMRA_SELFTEST_NONCE: session.nonce,
    SHOMRA_SELFTEST_CANARY: canary,
    SHOMRA_SELFTEST_OUT: receipt,
  };

  const startedAt = Date.now();
  return new Promise((done) => {
    let child;
    try {
      child = spawn(command, { shell: true, cwd, env: childEnv, windowsHide: true });
    } catch (e) {
      return done({ code: null, stdout: '', stderr: '', ms: 0, receipts: [], spawnError: e?.message ?? String(e) });
    }
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, selftestTimeoutMs());
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('error', (e) => {
      clearTimeout(timer);
      done({ code: null, stdout, stderr, ms: Date.now() - startedAt, receipts: [], spawnError: e?.message ?? String(e) });
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      done({
        code,
        stdout,
        stderr,
        ms: Date.now() - startedAt,
        receipts: readReceipts(receipt),
        spawnError: timedOut ? `the hook did not answer within ${selftestTimeoutMs()}ms` : null,
      });
    });
    child.stdin.on('error', () => { /* a hook that exits before reading stdin is its own finding */ });
    child.stdin.end(JSON.stringify(payload));
  });
}
