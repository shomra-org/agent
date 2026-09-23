import { scanChatTemplate } from '../detect/signals/chat-template.mjs';
import { localModelConfig } from '../detect/signals/model-config.mjs';
import { modelSurface } from './runtime.mjs';

const BLOB_REF = /^(\s*(?:FROM|ADAPTER)\s+)\S*?[\\/]models[\\/]blobs[\\/]sha256[-:]([0-9a-f]{64})\s*$/gim;
const REFUSE = new Set(['CRITICAL', 'HIGH']);

export function vetSurface(name, surface) {
  const findings = [];
  const push = (severity, title, where) => findings.push({ severity, title, where });
  if (surface?.modelfile) {
    const modelfile = surface.modelfile.replace(BLOB_REF, (_, lead, hex) => `${lead}ollama-blob@sha256:${hex}`);
    for (const f of localModelConfig(modelfile, { path: 'Modelfile' })) push(f.severity, f.title, 'Modelfile');
  } else if (surface?.template) {
    for (const f of scanChatTemplate(surface.template, name, { sink: 'TEMPLATE', renderer: 'the runtime' })) push(f.severity, f.title, 'template');
  }
  if (surface?.chatTemplate) {
    for (const f of scanChatTemplate(surface.chatTemplate, name, { sink: 'tokenizer.chat_template', renderer: 'the runtime' })) push(f.severity, f.title, 'chat template');
  }
  const seen = new Set();
  const unique = findings.filter((f) => (seen.has(f.title) ? false : (seen.add(f.title), true)));
  return { read: !!surface?.read, findings: unique, refused: unique.some((f) => REFUSE.has(f.severity)) };
}

export async function vetModel(rt, name) {
  try {
    return vetSurface(name, await modelSurface(rt, name));
  } catch (error) {
    return { read: false, findings: [], refused: false, error: String(error?.message ?? error).slice(0, 160) };
  }
}
