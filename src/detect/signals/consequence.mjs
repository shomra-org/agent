/**
 * How much a tool call COSTS if it is wrong - the ladder the backend grades on,
 * mirrored here so the client can decide it OFFLINE.
 *
 * ⚠ THIS IS THE FAIL-CLOSED KEY. The hook fails open by design: an agent that
 * hard-stops on an unreachable SaaS backend is one nobody keeps installed. But
 * failing open on EVERY call means an attacker buys a bypass with a slow input
 * or a rate limit. Grading the consequence on-machine is what lets the hook
 * keep ordinary work flowing while still refusing a destructive call it could
 * not get screened.
 *
 * ⚠ It is a MIRROR of src/modules/runtime/intent/domain/consequence.ts and must
 * stay one - pinned by the backend's test/parity/consequence-mirror-bench.mjs.
 * Drift here is asymmetric in the same way every other mirror is: stricter than
 * the server blocks work no server verdict would have blocked, and looser puts
 * a hole in the floor at exactly the moment the floor is all there is.
 */
const SEVERE_VERB = /\b(delete|destroy|drop|purge|revoke|terminate|shutdown|wipe|erase|truncate|force[-_]?push|rm)\b/i;

const MATERIAL_VERB =
  /\b(transfer|pay|payment|refund|charge|invoice|wire|send|email|post|publish|deploy|release|merge|approve|grant|invite|share|upload|export)\b/i;

const AUTHORITY_GRANT =
  /\b(assume|impersonate|escalate|elevate|sudo|attach|grant|bind|add|put|set|create|assign)\s+(?:\w+\s+){0,2}(role|member|policy|binding|permission|principal|group|user|iam|owner|admin|access)\b/i;

const PRIVILEGED_TARGET =
  /\b(admin|administrator|owner|owners|root|superuser|orgadmin|administratoraccess|poweruser|cluster[-_]?admin|iam:\*)\b/i;

const PERSISTENCE_TARGET =
  /(^|\/)\.(ssh|aws|kube)\/|authorized_keys|\.bashrc|\.zshrc|\.profile|crontab|\/etc\/(sudoers|passwd|shadow)|systemd|(^|\/)\.env(\.|$)/i;

const PRODUCTION = /\b(prod|production|live|main|master|release)\b/i;

/* ⚠ `force[-_]?push` never matched the way anybody writes it, so `git push
 * --force origin main` graded MATERIAL and the fail-closed rung never covered
 * it. --force-with-lease is included on purpose: it refuses when the remote
 * moved, which makes it safer, not less destructive. */
const FORCE_PUSH = /\bgit\s+push\b[^|;&\n]*?\s--?f(?:orce(?:-with-lease)?)?\b/i;

export function classifyConsequence(input) {
  const leaf = String(input.tool ?? '').replace(/^mcp__[^_]+__/, '');
  const raw = `${leaf} ${input.args ?? ''}`;
  const blob = raw.replace(/[_-]+/g, ' ').replace(/([a-z0-9])([A-Z])/g, '$1 $2');

  if (typeof input.amount === 'number' && input.amount > 0) {
    return SEVERE_VERB.test(blob) ? 'severe' : 'material';
  }
  if (PERSISTENCE_TARGET.test(raw)) return 'severe';
  if (SEVERE_VERB.test(blob) || FORCE_PUSH.test(raw)) return 'severe';
  if (AUTHORITY_GRANT.test(blob)) return PRIVILEGED_TARGET.test(blob) ? 'severe' : 'material';
  if (input.isShell) return 'material';
  if (MATERIAL_VERB.test(blob)) return 'material';
  if (input.isEgress) return 'material';
  if (input.actionId && PRODUCTION.test(blob) && MATERIAL_VERB.test(input.actionId)) return 'severe';
  return 'routine';
}
