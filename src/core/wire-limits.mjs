
import { createHash } from 'node:crypto';

export const WIRE_LIMITS = {
  asset: { name: 255, identifier: 1024, content: 200_000 },
  artifact: { name: 200, path: 1024, content: 200_000 },
  artifactFile: { path: 1024, content: 200_000 },
};

const FINGERPRINT = 12;

export function clampField(value, max) {
  if (typeof value !== 'string' || value.length <= max) return value;
  const digest = createHash('sha256').update(value).digest('hex').slice(0, 10);
  return `${value.slice(0, Math.max(1, max - FINGERPRINT))}…#${digest}`;
}

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

            ...(typeof f.content === 'string' && f.content.length > F.content
              ? { content: f.content.slice(0, F.content) }
              : {}),
          })),
        }
      : {}),
  };
}
