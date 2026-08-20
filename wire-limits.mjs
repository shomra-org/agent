/**
 * THE WIRE CONTRACT — the field caps `AgentReportDto` enforces server-side, and
 * one function that makes it impossible for a collector to violate them.
 *
 * ── Why this exists ─────────────────────────────────────────────────────────
 *
 * A report is validated ALL-OR-NOTHING. One field over its limit and the backend
 * rejects the entire payload, so a single unusual row on one machine costs that
 * machine's whole inventory — every asset, every artifact, and the check-in that
 * carried them. The estate then shows a machine that has simply stopped
 * reporting, which is indistinguishable from one that was switched off.
 *
 * That is not hypothetical. It shipped: an MCP server configured to launch via an
 * inline `node -e '<1675 characters of JavaScript>'` produced an identifier past
 * the 1024-char cap, and the response was
 *
 *     400 assets.1.identifier must be shorter than or equal to 1024 characters
 *
 * — 81 assets and 29 artifacts discarded over one field. The collector had no
 * idea a limit existed, which is the actual defect: the limits live in a DTO in
 * another repository, and every discoverer here was quietly expected to know them.
 *
 * ── Truncation must preserve IDENTITY ───────────────────────────────────────
 *
 * ⚠ A plain `.slice(0, 1024)` is the wrong fix and it is the obvious one. An
 * asset's identifier is its DEDUP KEY — `discoverAll` keys on `type::identifier`
 * and the backend keys `Asset` on it too. Two inline-script servers that share a
 * 1024-character prefix (which any two `node -e` launchers with the same preamble
 * do) would collapse into ONE asset, and the survivor would be whichever was
 * discovered last. That turns a validation error into silent data loss, which is
 * strictly worse: the 400 at least announced itself.
 *
 * So an over-long value is truncated AND fingerprinted — the head, an ellipsis,
 * and a short digest of the ORIGINAL. Distinct values stay distinct, the same
 * value produces the same key on every check-in (so nothing churns), and the
 * result reads as obviously abbreviated rather than as a complete string.
 *
 * ⚠ The digest is of the WHOLE original, never of the discarded tail. Hashing the
 * tail alone would make two values differing only in their head collide.
 */

import { createHash } from 'node:crypto';

/**
 * Caps from `Dragox.Backend/src/agent/dto/report.dto.ts`.
 *
 * ⚠ MIRRORED, not imported — the DTO is in another repo and this CLI ships
 * standalone. `test/endpoint-artifacts/endpoint-artifacts-bench.mjs` pins the two
 * together, the same way `wire-contract-bench` does for the guard ledger: a cap
 * that drifts here is a rejected report on every machine at once.
 */
export const WIRE_LIMITS = {
  asset: { name: 255, identifier: 1024, content: 200_000 },
  artifact: { name: 200, path: 1024, content: 200_000 },
  artifactFile: { path: 1024, content: 200_000 },
};

/** How much of the cap the fingerprint suffix is allowed to spend. */
const FINGERPRINT = 12; // "…#" + 10 hex

/**
 * Bring one string inside `max`, keeping distinct inputs distinct.
 *
 * Returns the value untouched when it already fits — the overwhelmingly common
 * case, and the one that must cost nothing.
 */
export function clampField(value, max) {
  if (typeof value !== 'string' || value.length <= max) return value;
  const digest = createHash('sha256').update(value).digest('hex').slice(0, 10);
  return `${value.slice(0, Math.max(1, max - FINGERPRINT))}…#${digest}`;
}

/**
 * Clamp one discovered asset to the wire contract.
 *
 * ⚠ `content` is TRUNCATED WITHOUT a fingerprint, unlike the identity fields. It
 * is analysed, not keyed on, so a digest in the body would be a foreign token
 * inside a document the detector is about to read — and a hash appended to a JSON
 * blob makes it unparseable. Losing the tail of an over-long body is a coverage
 * loss the analyzer can survive; losing the row is not.
 */
export function clampAsset(asset) {
  const L = WIRE_LIMITS.asset;
  return {
    ...asset,
    name: clampField(asset.name, L.name),
    ...(asset.identifier != null ? { identifier: clampField(asset.identifier, L.identifier) } : {}),
    ...(typeof asset.content === 'string' && asset.content.length > L.content
      ? { content: asset.content.slice(0, L.content) }
      : {}),
  };
}

/** Clamp one agent artifact and its bundled files. Same rules as above. */
export function clampArtifact(artifact) {
  const L = WIRE_LIMITS.artifact;
  const F = WIRE_LIMITS.artifactFile;
  return {
    ...artifact,
    name: clampField(artifact.name, L.name),
    path: clampField(artifact.path, L.path),
    ...(typeof artifact.content === 'string' && artifact.content.length > L.content
      ? { content: artifact.content.slice(0, L.content) }
      : {}),
    ...(Array.isArray(artifact.files)
      ? {
          files: artifact.files.map((f) => ({
            ...f,
            path: clampField(f.path, F.path),
            // ⚠ `content: null` means BINARY AND DELIBERATELY UNREAD. It must
            // survive as null — coercing it to a string here would report an
            // unread payload as an empty, and therefore harmless, one.
            ...(typeof f.content === 'string' && f.content.length > F.content
              ? { content: f.content.slice(0, F.content) }
              : {}),
          })),
        }
      : {}),
  };
}
