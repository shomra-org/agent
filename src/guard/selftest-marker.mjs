import fs from 'node:fs';

/**
 *  HOW A SELF-TEST CANARY IS TOLD APART FROM A REAL CALL, on both sides.
 *
 * `shomra selftest` spawns the INSTALLED hook exactly as the vendor would, so
 * the only thing it can hand the hook is stdin and an environment. Two env vars
 * carry the session: the nonce the server issued (sent with the call, so the
 * server can answer from its simulator instead of enforcing and recording), and
 * a receipt file the hook appends what it did to, so the self-test can assert on
 * a flow that otherwise leaves no trace but an exit code.
 *
 * ⚠ THE NONCE CHANGES NOTHING ABOUT THE DECISION PATH. The hook still screens
 * locally, still decides for itself whether to escalate, still honours the
 * breaker and strict mode. A canary that stays local is a real reading, and
 * reporting it as one is the whole point - the alternative is a self-test that
 * proves the code it forced to run.
 *
 * ⚠ AND IT IS NOT A PERMISSION. The server accepts the simulation path only for
 * a nonce it issued, to this machine, on a payload carrying that nonce's canary
 * marker; anything else is processed as a live call and recorded. Nothing here
 * can widen that - the endpoint cannot vouch for itself.
 */

export function selftestSession(env = process.env) {
  const nonce = String(env.SHOMRA_SELFTEST_NONCE ?? '').trim();
  if (!nonce || nonce.length > 200) return null;
  return {
    nonce,
    canary: String(env.SHOMRA_SELFTEST_CANARY ?? '').trim() || null,
    out: String(env.SHOMRA_SELFTEST_OUT ?? '').trim() || null,
  };
}

/** The field the hook adds to a guard body during a self-test, and nothing otherwise. */
export function selftestField(env = process.env) {
  const s = selftestSession(env);
  if (!s) return {};
  return { selftest: { nonce: s.nonce, ...(s.canary ? { canary: s.canary } : {}) } };
}

/**
 * One line of what the hook did with a canary. ⚠ Append-only and never allowed
 * to fail the call: a self-test that changes how the guard behaves is measuring
 * itself.
 */
export function recordSelftest(row, env = process.env) {
  const s = selftestSession(env);
  if (!s?.out) return;
  try {
    fs.appendFileSync(s.out, `${JSON.stringify({ at: new Date().toISOString(), canary: s.canary, ...row })}\n`);
  } catch {
    /* an unwritable receipt costs the assertion, never the call */
  }
}
