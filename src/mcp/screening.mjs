import { downrankCodeContext, grade, localScan } from '../detect/guard-signals.mjs';
import { safeJson } from './jsonrpc.mjs';

const MAX_EXTRACT_DEPTH = 12;
const MAX_EXTRACT_BYTES = 256 * 1024;

export const LISTING_KEY = {
  'tools/list': 'tools',
  'resources/list': 'resources',
  'resources/templates/list': 'resourceTemplates',
  'prompts/list': 'prompts',
};

export const RESULT_METHODS = new Set(['resources/read', 'prompts/get', 'completion/complete']);

function extractResultText(value, depth = 0, collected = []) {
  if (depth > MAX_EXTRACT_DEPTH || collected.join('').length > MAX_EXTRACT_BYTES) return collected;
  if (typeof value === 'string') {
    collected.push(value);
    return collected;
  }
  if (Array.isArray(value)) {
    for (const item of value) extractResultText(item, depth + 1, collected);
    return collected;
  }
  if (value && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) {
      if (key === 'blob') continue;
      if (typeof item === 'string') collected.push(item);
      else extractResultText(item, depth + 1, collected);
    }
  }
  return collected;
}

function isUnmaskedThreat(finding) {
  return !finding.codeContext && (finding.severity === 'CRITICAL' || finding.category === 'injection');
}

export function screenResult(result) {
  const text = extractResultText(result).join('\n');
  if (!text.trim()) return { blocked: false };

  const scan = localScan(text);
  if (!scan.findings.some(isUnmaskedThreat)) return { blocked: false };

  const ranked = downrankCodeContext(scan.findings);
  const worst = ranked.find((f) => f.severity === 'CRITICAL' && !f.codeContext)
    ?? ranked.find((f) => f.category === 'injection' && !f.codeContext)
    ?? ranked[0];
  return { blocked: true, label: worst?.label || 'malicious content' };
}

function descriptorText(entry, method) {
  const descriptor = entry ?? {};
  const parts = method === 'tools/list'
    ? [descriptor.name ?? '', descriptor.description ?? '', safeJson(descriptor.annotations), safeJson(descriptor.inputSchema)]
    : [
      descriptor.name ?? '', descriptor.title ?? '', descriptor.description ?? '',
      descriptor.uri ?? '', descriptor.uriTemplate ?? '', safeJson(descriptor.arguments),
    ];
  return parts.filter(Boolean).join('\n');
}

function descriptorLabel(entry) {
  return String(entry?.name ?? entry?.uri ?? entry?.uriTemplate ?? 'unnamed');
}

function isPoisonedDescriptor(entry, method) {
  const text = descriptorText(entry, method);
  if (!text.trim()) return false;
  const { findings } = localScan(text, { categories: ['injection', 'secret', 'egress'] });
  return findings.some((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH');
}

export function screenListing(method, result, deniedTools = []) {
  const key = LISTING_KEY[method];
  const entries = key && Array.isArray(result?.[key]) ? result[key] : null;
  if (!entries) return { result, withheld: [], denied: [], total: 0 };

  const denySet = new Set(deniedTools ?? []);
  const kept = [];
  const withheld = [];
  const denied = [];
  for (const entry of entries) {
    if (method === 'tools/list' && denySet.has(String(entry?.name ?? ''))) {
      denied.push(String(entry.name));
    } else if (isPoisonedDescriptor(entry, method)) {
      withheld.push(descriptorLabel(entry));
    } else {
      kept.push(entry);
    }
  }
  if (!withheld.length && !denied.length) return { result, withheld: [], denied: [], total: entries.length };
  return { result: { ...result, [key]: kept }, withheld, denied, total: entries.length };
}

export function screenToolCallArguments(toolArguments) {
  const { findings } = localScan(safeJson(toolArguments), { categories: ['shell', 'injection', 'secret'] });
  if (grade(findings).verdict !== 'BLOCK') return { blocked: false };
  const label = findings.find((f) => f.severity === 'CRITICAL')?.label || 'dangerous tool call';
  return { blocked: true, label };
}
