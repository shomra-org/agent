import fs from 'node:fs';
import path from 'node:path';
import { listProcesses } from './coding-agents.mjs';
import { firstExisting } from './fs-read.mjs';
import { APPDATA, HOME, LOCALAPPDATA } from './platform.mjs';

export function discoverLocalRuntimes() {
  const runtimes = [
    { vendor: 'ollama', name: 'Ollama', dirs: [path.join(HOME, '.ollama'), path.join(LOCALAPPDATA, 'Ollama')], modelsDir: path.join(HOME, '.ollama', 'models', 'manifests'), proc: ['ollama'] },
    { vendor: 'lmstudio', name: 'LM Studio', dirs: [path.join(HOME, '.lmstudio'), path.join(HOME, '.cache', 'lm-studio'), path.join(LOCALAPPDATA, 'LM Studio')], proc: ['lm studio', 'lmstudio', 'lms'] },
    { vendor: 'jan', name: 'Jan', dirs: [path.join(HOME, 'jan'), path.join(HOME, '.jan'), path.join(APPDATA, 'Jan')], proc: ['jan'] },
    { vendor: 'gpt4all', name: 'GPT4All', dirs: [path.join(HOME, '.cache', 'gpt4all'), path.join(HOME, 'Library', 'Application Support', 'nomic.ai', 'GPT4All'), path.join(LOCALAPPDATA, 'nomic.ai', 'GPT4All')], proc: ['gpt4all'] },
    { vendor: 'huggingface', name: 'Hugging Face cache', dirs: [path.join(HOME, '.cache', 'huggingface'), path.join(process.env.HF_HOME || '', 'hub')], proc: [] },
    { vendor: 'localai', name: 'LocalAI', dirs: [path.join(HOME, '.localai')], proc: ['local-ai', 'localai'] },
    { vendor: 'textgen', name: 'Text Generation WebUI', dirs: [], proc: ['text-generation', 'oobabooga'] },
    { vendor: 'vllm', name: 'vLLM', dirs: [], proc: ['vllm'] },
  ];
  const procs = listProcesses();
  const assets = [];
  for (const r of runtimes) {
    const at = firstExisting(r.dirs);
    const running = r.proc.some((tok) => procs.some((p) => p.includes(tok)));
    if (!at && !running) continue;
    const meta = { category: 'local-runtime', detectedAt: at || null, running };
    if (r.vendor === 'ollama' && r.modelsDir) meta.models = ollamaModels(r.modelsDir);
    assets.push({ type: 'AI_TOOL', name: r.name, identifier: at || `proc:${r.vendor}`, vendor: r.vendor, metadata: meta });
  }
  return assets;
}

function ollamaModels(manifestsDir) {
  const out = [];
  const walk = (dir, depth) => {
    if (depth > 5 || out.length > 100) return;
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) walk(full, depth + 1);
      else if (e.isFile()) {

        const rel = path.relative(manifestsDir, full).split(path.sep);
        if (rel.length >= 2) out.push(`${rel.slice(1, -1).join('/')}:${rel[rel.length - 1]}`);
      }
    }
  };
  walk(manifestsDir, 0);
  return out.slice(0, 100);
}
