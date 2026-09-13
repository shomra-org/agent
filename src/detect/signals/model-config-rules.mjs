// GENERATED MIRROR of Dragox.Backend model-formats/model-config-rules.ts (types stripped, imports swapped).
// Do not hand-edit the rules here - change the backend file and regenerate, so
// `shomra gate` and the platform grade a model config identically.
import { parseYaml } from '../../core/yaml-lite.mjs';
import { inspectText } from './inspect-shim.mjs';

                               
               
               
                  
                     
                
            
            
                
             
          
             
                 

                                     
                 
                                                                                                                                   
                                                   
                
                 
                      
              
                        
                                    
 

const MAX_WALK_NODES = 20_000;
const isObj = (v         )                           => !!v && typeof v === 'object' && !Array.isArray(v);
const base = (p        ) => String(p ?? '').replace(/\\/g, '/').split('/').pop() ?? '';

/* ─── what counts as a host-execution primitive ─────────────────────────── */

const DANGEROUS_CALLABLE_RE =
  /^(?:builtins?\.|__builtin__\.)?(?:eval|exec|compile|__import__|open|getattr|setattr|breakpoint|input)$|^(?:os|posix|nt|subprocess|pty|shutil|socket|runpy|importlib|imp|pickle|cPickle|dill|marshal|code|codeop|ctypes|multiprocessing|webbrowser|sys|commands|platform\.popen|pdb|asyncio\.subprocess)(?:\.|$)|^(?:builtins?|__builtin__)$|^(?:keras\.utils\.get_file|tensorflow\.keras\.utils\.get_file|tf\.keras\.utils\.get_file|keras\.src\.utils\.file_utils\.get_file|torch\.hub\.load|torch\.load|numpy\.load|joblib\.load)$|^(?:os\.system|os\.popen|os\.exec\w*|os\.spawn\w*)$/i;

const isDangerousCallable = (v        ) => DANGEROUS_CALLABLE_RE.test(String(v ?? '').trim().replace(/^:/, ''));

/* ─── classification ────────────────────────────────────────────────────── */

const HF_JSON = new Set([
  'config.json', 'generation_config.json', 'processor_config.json', 'preprocessor_config.json',
  'config_sentence_transformers.json', 'feature_extractor_config.json', 'image_processor_config.json', 'video_preprocessor_config.json',
]);
const TOKENIZER_JSON = new Set(['tokenizer_config.json', 'special_tokens_map.json', 'tokenizer.json', 'added_tokens.json']);
const VLLM_KEYS = ['tensor-parallel-size', 'tensor_parallel_size', 'gpu-memory-utilization', 'gpu_memory_utilization', 'max-model-len', 'max_model_len', 'served-model-name', 'served_model_name', 'trust-remote-code', 'enable-lora', 'kv-transfer-config', 'allowed-local-media-path'];
const TORCHSERVE_KEYS = /^\s*(?:inference_address|management_address|metrics_address|model_store|load_models|allowed_urls|disable_token_authorization)\s*=/m;

export function modelConfigFormat(path        , text                           )                           {
  const b = base(path);
  const lower = b.toLowerCase();
  const t = String(text ?? '');
  if (!t.trim()) return null;
  if (lower === 'adapter_config.json') return 'peft-adapter';
  if (lower === 'model_index.json' && /"_class_name"/.test(t)) return 'diffusers-index';
  if (lower === 'modules.json' && /"type"\s*:\s*"/.test(t) && /"path"\s*:/.test(t)) return 'st-modules';
  if (TOKENIZER_JSON.has(lower)) return 'tokenizer';
  if (HF_JSON.has(lower)) return 'hf-config';
  if (b === 'MLmodel' || lower === 'mlmodel') return 'mlflow';
  if (lower === 'config.pbtxt') return 'triton';
  if (lower.endsWith('.properties') && TORCHSERVE_KEYS.test(t)) return 'torchserve';
  if (lower === 'bentofile.yaml' || lower === 'bentofile.yml') return 'bentoml';
  if (/\.ya?ml$/i.test(lower)) {
    if (/^model_list\s*:/m.test(t)) return 'litellm';
    if (VLLM_KEYS.filter((k) => new RegExp(`^${k.replace(/[-_]/g, '[-_]')}\\s*:`, 'm').test(t)).length >= 2) return 'vllm';
    if (/(^|\s)_target_\s*:|!!python\//.test(t)) return 'hydra-yaml';
  }
  return null;
}

/* ─── generic walkers ───────────────────────────────────────────────────── */

const MAX_WALK_DEPTH = 64;

function walk(node         , visit                                                     , path = '', budget = { n: 0 }, depth = 0)       {
  if (budget.n++ > MAX_WALK_NODES || depth > MAX_WALK_DEPTH || node == null || typeof node !== 'object') return;
  if (Array.isArray(node)) {
    node.forEach((v, i) => walk(v, visit, `${path}[${i}]`, budget, depth + 1));
    return;
  }
  for (const [k, v] of Object.entries(node)) {
    const p = path ? `${path}.${k}` : k;
    visit(k, v, p);
    walk(v, visit, p, budget, depth + 1);
  }
}

/** Hydra / OmegaConf / PyTorchModelHubMixin instantiation: `_target_` anywhere in the tree. */
function targetFindings(doc         , file        , opts                              )                       {
  const out                       = [];
  const dangerous                                     = [];
  const foreign                                     = [];
  walk(doc, (k, v, p) => {
    if ((k === '_target_' || k === '_partial_target_' || k === 'target_class') && typeof v === 'string') {
      if (isDangerousCallable(v)) dangerous.push({ path: p, target: v });
      else foreign.push({ path: p, target: v });
    }
  });
  if (dangerous.length) {
    out.push({
      ruleId: 'model_config.target_exec',
      cls: 'SANDBOX', severity: 'CRITICAL', cwe: 'CWE-94', anchor: dangerous[0].target,
      title: `Model config instantiates a host-execution primitive (${dangerous[0].target})`,
      detail:
        `\`${dangerous[0].path}: ${dangerous[0].target}\` in ${file}. A Hydra/OmegaConf \`_target_\` is IMPORTED AND CALLED when the config is instantiated - loading the model is enough; this is the NeMo (CVE-2025-23304) and Uni2TS/PyTorchModelHubMixin class of config-to-RCE.`,
      remediation: 'Do not load this model. A model config never needs to name os/subprocess/eval/builtins; restore the upstream config and load with an instantiate() that allowlists targets.',
      evidence: { targets: dangerous.slice(0, 8), file },
    });
  }
  if (!dangerous.length && foreign.length && opts.inWeightsConfig) {
    out.push({
      ruleId: 'model_config.target_instantiation',
      cls: 'SANDBOX', severity: 'MEDIUM', cwe: 'CWE-470', anchor: foreign[0].target,
      title: `Model config instantiates classes by import path (${foreign[0].target})`,
      detail:
        `${file} names ${foreign.length} class${foreign.length === 1 ? '' : 'es'} via \`_target_\` (${foreign.slice(0, 3).map((f) => f.target).join(', ')}). Whatever loads this config imports and constructs them, so the config - not the code - decides what runs. Ordinary for NeMo/Lightning checkpoints; the risk is a republished config that swaps the path.`,
      remediation: 'Pin the checkpoint to a reviewed revision and load with an allowlist of permitted `_target_` namespaces (e.g. NeMo safe_instantiate).',
      evidence: { targets: foreign.slice(0, 8), file },
    });
  }
  return out;
}

/* ─── Hugging Face configs ──────────────────────────────────────────────── */

const HUB_REPO_RE = /^[A-Za-z0-9][\w.-]*\/[\w.-]+(?:@[\w.-]+)?(?::[\w.-]+)?$/;
const TRUSTED_KERNEL_ORGS = /^kernels-community\//i;

function hfConfigFindings(doc     , file        )                       {
  const out                       = [];
  if (!isObj(doc)) return out;

  const kernels                                   = [];
  walk(doc, (k, v) => {
    if (typeof v === 'string' && /^_?attn_implementation(?:_internal|_autoset)?$|^_?(?:kernel|kernels)(?:_repo|_config)?$/.test(k) && HUB_REPO_RE.test(v.trim())) kernels.push({ key: k, value: v.trim() });
  });
  for (const kx of kernels.slice(0, 3)) {
    const privateKey = kx.key.startsWith('_');
    out.push({
      ruleId: privateKey ? 'model_config.private_kernel_injection' : 'model_config.hub_kernel',
      cls: 'SANDBOX',
      severity: privateKey ? 'CRITICAL' : TRUSTED_KERNEL_ORGS.test(kx.value) ? 'MEDIUM' : 'HIGH',
      cwe: 'CWE-829', anchor: kx.key,
      title: privateKey
        ? `Model config smuggles a kernel repo through a private key (${kx.key} = ${kx.value})`
        : `Model config loads attention kernels from a Hub repo (${kx.value})`,
      detail: privateKey
        ? `\`${kx.key}\` is an internal transformers attribute, never part of a published config. Set in config.json it makes the \`kernels\` loader download and import \`${kx.value}\` when the model loads - remote code that bypasses trust_remote_code (reported against transformers 4.56-5.2, fixed in 5.3.0).`
        : `\`${kx.key}: ${kx.value}\` makes transformers fetch and import compiled/Python kernels from that repository at load time - code execution decided by the config${TRUSTED_KERNEL_ORGS.test(kx.value) ? ' (from the kernels-community org, still unpinned code)' : ', from a publisher that is not the kernels-community org'}.`,
      remediation: privateKey
        ? 'Do not load this model; remove the private key and upgrade transformers to 5.3.0 or later.'
        : 'Pin the kernel repo to a reviewed revision, or drop the key and use a built-in attention implementation (sdpa / flash_attention_2).',
      evidence: { key: kx.key, repo: kx.value, file },
    });
  }

  out.push(...kerasFindings(doc, file));
  out.push(...targetFindings(doc, file, { inWeightsConfig: true }));
  return out;
}

function kerasFindings(doc     , file        )                       {
  const looksKeras = isObj(doc) && (typeof doc.keras_version === 'string' || (typeof doc.class_name === 'string' && isObj(doc.config) && (Array.isArray(doc.config.layers) || 'layers' in doc.config)));
  if (!looksKeras) return [];
  const lambdas           = [];
  const foreign           = [];
  const dangerous           = [];
  walk(doc, (k, v) => {
    if (k === 'class_name' && v === 'Lambda') lambdas.push('Lambda');
    if ((k === 'module' || k === 'registered_name' || k === 'function' || k === 'fn') && typeof v === 'string') {
      if (isDangerousCallable(v) || /(^|\.)get_file$/.test(v)) dangerous.push(v);
      else if (k === 'module' && !/^(?:keras|tf_keras|tensorflow|keras_hub|keras_nlp|keras_cv|builtins?$)/.test(v)) foreign.push(v);
    }
  });
  const out                       = [];
  if (dangerous.length) {
    out.push({
      ruleId: 'keras.config_arbitrary_import', cls: 'SANDBOX', severity: 'CRITICAL', cwe: 'CWE-94', anchor: dangerous[0],
      title: `Keras config imports a host-execution function (${dangerous[0]})`,
      detail: `${file} names \`${dangerous[0]}\` as a layer module/function. Keras resolves these on load even with safe_mode (CVE-2025-1550, fixed 3.9) and \`keras.utils.get_file\` was reused for arbitrary file writes (CVE-2025-8747, fixed 3.11).`,
      remediation: 'Do not load this model. Upgrade Keras to 3.11+ and load only models whose config names keras.* layers.',
      evidence: { modules: dangerous.slice(0, 6), file },
    });
  }
  if (lambdas.length) {
    out.push({
      ruleId: 'keras.config_lambda', cls: 'SANDBOX', severity: 'HIGH', cwe: 'CWE-502', anchor: '"Lambda"',
      title: 'Keras config contains a Lambda layer (serialized Python code)',
      detail: `${file} declares ${lambdas.length} Lambda layer${lambdas.length === 1 ? '' : 's'}. A Lambda carries marshalled Python bytecode that runs on load; safe_mode blocks it for .keras but NOT for .h5 (CVE-2025-9905) or Keras 2 (CVE-2024-3660).`,
      remediation: 'Replace the Lambda with a registered custom layer, load with safe_mode=True on Keras 3.11.3+, and never load the .h5 form of this model.',
      evidence: { lambdas: lambdas.length, file },
    });
  }
  if (!dangerous.length && foreign.length) {
    out.push({
      ruleId: 'keras.config_foreign_module', cls: 'SANDBOX', severity: 'MEDIUM', cwe: 'CWE-470', anchor: foreign[0],
      title: `Keras config resolves layers from a non-Keras module (${foreign[0]})`,
      detail: `${file} deserializes layers from \`${[...new Set(foreign)].slice(0, 3).join(', ')}\`, which is imported on load. Ordinary for a registered custom layer; a swapped module name is how config-injection gets code into a Keras load.`,
      remediation: 'Confirm the module is your own registered layer package and pin it.',
      evidence: { modules: [...new Set(foreign)].slice(0, 6), file },
    });
  }
  return out;
}

/* ─── tokenizer files ──────────────────────────────────────────────────── */

const TOKENISH_RE = /^(?:<[^<>\s]{1,40}>|<\|[^|]{1,40}\|>|\[[A-Z_\/]{1,24}\]|▁?\S{1,24})$/;

function tokenizerFindings(doc     , file        )                       {
  const out                       = [];
  const contents           = [];
  const collect = (v         ) => {
    if (typeof v === 'string') contents.push(v);
    else if (isObj(v) && typeof v.content === 'string') contents.push(v.content);
  };
  if (isObj(doc)) {
    for (const t of Array.isArray(doc.added_tokens) ? doc.added_tokens.slice(0, 5000) : []) collect(t);
    for (const t of Array.isArray(doc.additional_special_tokens) ? doc.additional_special_tokens : []) collect(t);
    for (const k of ['bos_token', 'eos_token', 'unk_token', 'sep_token', 'pad_token', 'cls_token', 'mask_token']) collect(doc[k]);
    if (isObj(doc.added_tokens_decoder)) for (const t of Object.values(doc.added_tokens_decoder).slice(0, 5000)) collect(t);
    if (file.toLowerCase().endsWith('added_tokens.json')) for (const k of Object.keys(doc).slice(0, 5000)) contents.push(k);
  }
  const prose = contents.filter((c) => !TOKENISH_RE.test(c.trim()) && (c.trim().split(/\s+/).length >= 4 || /https?:\/\//i.test(c)));
  const injected = prose.filter((c) => /https?:\/\//i.test(c) || inspectText(c, { categories: ['injection'] }).matches.length > 0);
  if (injected.length) {
    out.push({
      ruleId: 'tokenizer.special_token_payload', cls: 'INJECTION_FLAW', severity: 'HIGH', cwe: 'CWE-94', anchor: injected[0].slice(0, 40),
      title: 'Tokenizer defines a special token that carries instructions or a URL',
      detail: `${file} registers ${injected.length} added/special token${injected.length === 1 ? '' : 's'} whose text is an instruction or a link (${JSON.stringify(injected[0].slice(0, 80))}). A special token is emitted and consumed as ONE unit the model was trained to obey - tokenizer tampering survives fine-tuning and is invisible in any prompt.`,
      remediation: 'Compare this tokenizer against the base model\'s published tokenizer and restore it; do not serve a model whose special tokens were edited.',
      evidence: { tokens: injected.slice(0, 5).map((t) => t.slice(0, 120)), file },
    });
  } else if (prose.length >= 3) {
    out.push({
      ruleId: 'tokenizer.prose_special_tokens', cls: 'INJECTION_FLAW', severity: 'MEDIUM', cwe: 'CWE-94', anchor: prose[0].slice(0, 40),
      title: 'Tokenizer defines sentence-length special tokens',
      detail: `${file} adds ${prose.length} special tokens that read as sentences rather than markers (${JSON.stringify(prose[0].slice(0, 60))}). Legitimate added tokens are delimiters; whole phrases as single tokens are a tokenizer-tampering pattern.`,
      remediation: 'Diff against the base model\'s tokenizer and confirm who added these tokens and why.',
      evidence: { tokens: prose.slice(0, 5).map((t) => t.slice(0, 120)), file },
    });
  }
  return out;
}

/* ─── PEFT adapters ─────────────────────────────────────────────────────── */

function peftFindings(doc     , file        )                       {
  const out                       = [];
  if (!isObj(doc)) return out;
  if (doc.auto_mapping != null && (isObj(doc.auto_mapping) || typeof doc.auto_mapping === 'string')) {
    out.push({
      ruleId: 'peft.auto_mapping', cls: 'SANDBOX', severity: 'HIGH', cwe: 'CWE-829', anchor: 'auto_mapping',
      title: 'Adapter config binds a custom class (auto_mapping)',
      detail: `${file} sets \`auto_mapping\`, which points PEFT at a custom model/tuner class shipped with the adapter - imported when the adapter loads.`,
      remediation: 'Load only adapters that use built-in PEFT tuners, or read and pin the referenced class.',
      evidence: { autoMapping: doc.auto_mapping, file },
    });
  }
  const baseModel = typeof doc.base_model_name_or_path === 'string' ? doc.base_model_name_or_path.trim() : '';
  if (/^https?:\/\//i.test(baseModel)) {
    out.push({
      ruleId: 'peft.base_model_url', cls: 'BAD_DEPENDENCY', severity: 'MEDIUM', cwe: 'CWE-494', anchor: baseModel,
      title: `Adapter pulls its base model from a URL (${baseModel.slice(0, 80)})`,
      detail: `Loading this adapter fetches the base weights from \`${baseModel}\`, outside any model registry, unverified by digest.`,
      remediation: 'Point base_model_name_or_path at a registry repo pinned by revision.',
      evidence: { baseModel, file },
    });
  } else if (HUB_REPO_RE.test(baseModel) && !doc.revision) {
    out.push({
      ruleId: 'peft.unpinned_base', cls: 'BAD_DEPENDENCY', severity: 'LOW', cwe: 'CWE-1357', anchor: baseModel,
      title: `Adapter loads an unpinned base model (${baseModel})`,
      detail: `\`base_model_name_or_path: ${baseModel}\` with no \`revision\`: loading the adapter pulls whatever that repo holds today - including an auto_map, a pickle or a chat template that were not there when the adapter was reviewed.`,
      remediation: 'Set `revision` to the reviewed base-model commit.',
      evidence: { baseModel, file },
    });
  }
  return out;
}

/* ─── diffusers model_index.json ────────────────────────────────────────── */

const DIFFUSERS_LIBS = new Set(['diffusers', 'transformers', 'peft', 'sentence_transformers', 'onnxruntime', 'onnxruntime.training', null       ]);

function diffusersFindings(doc     , file        )                       {
  const out                       = [];
  if (!isObj(doc)) return out;
  const custom           = [];
  if (Array.isArray(doc._class_name)) custom.push(`pipeline ${doc._class_name.join('.')}`);
  if (typeof doc.custom_pipeline === 'string' || doc.custom_pipeline != null) custom.push(`custom_pipeline ${String(doc.custom_pipeline)}`);
  for (const [k, v] of Object.entries(doc)) {
    if (k.startsWith('_') || !Array.isArray(v) || v.length !== 2) continue;
    const lib = v[0];
    if (!DIFFUSERS_LIBS.has(lib) && typeof lib === 'string') custom.push(`${k} → ${lib}.${v[1]}`);
  }
  if (custom.length) {
    out.push({
      ruleId: 'diffusers.custom_component', cls: 'SANDBOX', severity: 'HIGH', cwe: 'CWE-829', anchor: custom[0].split(/[ →.]/)[0],
      title: `Diffusion pipeline loads components from custom code (${custom[0]})`,
      detail: `${file} binds ${custom.slice(0, 3).join('; ')} - modules outside diffusers/transformers that from_pretrained imports. Two 2026 diffusers advisories let such code run WITHOUT trust_remote_code (a local snapshot, and \`custom_pipeline=None\` resolving to \`None.py\`), fixed in 0.38.0.`,
      remediation: 'Upgrade diffusers to 0.38.0+, pin the repo to a reviewed commit, and read every component .py it ships before loading.',
      evidence: { components: custom.slice(0, 10), file },
    });
  }
  return out;
}

/* ─── sentence-transformers modules.json ────────────────────────────────── */

function stModulesFindings(doc     , file        )                       {
  if (!Array.isArray(doc)) return [];
  const custom = doc.filter((m     ) => isObj(m) && typeof m.type === 'string' && !/^sentence_transformers\./.test(m.type)).map((m     ) => `${m.type}${m.path ? ` (${m.path})` : ''}`);
  if (!custom.length) return [];
  return [{
    ruleId: 'sentence_transformers.custom_module', cls: 'SANDBOX', severity: 'HIGH', cwe: 'CWE-829', anchor: custom[0].split(' ')[0],
    title: `Embedding model chains a custom module (${custom[0]})`,
    detail: `${file} lists modules outside sentence_transformers (${custom.slice(0, 3).join(', ')}); SentenceTransformer(...) imports them to build the pipeline. trust_remote_code=False was reported as not honoured for local paths, so a copied repo runs them regardless.`,
    remediation: 'Load only embedders whose modules.json names sentence_transformers.* modules, or pin and read the custom module.',
    evidence: { modules: custom.slice(0, 10), file },
  }];
}

/* ─── MLflow MLmodel ────────────────────────────────────────────────────── */

function mlflowFindings(doc     , file        )                       {
  const out                       = [];
  if (!isObj(doc) || !isObj(doc.flavors)) return out;
  const pyfunc = doc.flavors.python_function;
  const loader = isObj(pyfunc) && typeof pyfunc.loader_module === 'string' ? pyfunc.loader_module : null;
  if (loader && !/^mlflow\./.test(loader)) {
    out.push({
      ruleId: 'mlflow.custom_loader_module', cls: 'SANDBOX', severity: isDangerousCallable(loader) ? 'CRITICAL' : 'HIGH', cwe: 'CWE-829', anchor: loader,
      title: `MLflow model loads through a custom loader module (${loader})`,
      detail: `\`flavors.python_function.loader_module: ${loader}\` is imported and called by mlflow.pyfunc.load_model - the MLmodel file, not the caller, chooses what runs.`,
      remediation: 'Use a built-in mlflow.* flavor, or vendor and pin the loader module you have reviewed.',
      evidence: { loaderModule: loader, file },
    });
  }
  const pickled = Object.entries(doc.flavors).filter(([, f]               ) => isObj(f) && (f.cloudpickle_version || f.python_model || /pickle/i.test(String(f.serialization_format ?? f.pickled_model ?? ''))));
  if (pickled.length) {
    out.push({
      ruleId: 'mlflow.pickled_model', cls: 'SANDBOX', severity: 'MEDIUM', cwe: 'CWE-502', anchor: pickled[0][0],
      title: `MLflow model is deserialized from a pickle (${pickled.map(([k]) => k).join(', ')})`,
      detail: `The ${pickled.map(([k]) => k).join(', ')} flavor stores a (cloud)pickled object; loading it runs whatever the pickle's reduce calls - the class of CVE-2024-37052..37060.`,
      remediation: 'Load only MLflow models from a registry you control, and prefer a non-pickle flavor (ONNX, safetensors-backed transformers).',
      evidence: { flavors: pickled.map(([k]) => k), file },
    });
  }
  const codePaths = (isObj(pyfunc) && (pyfunc.code || pyfunc.code_paths)) || doc.code_paths;
  if (codePaths) {
    out.push({
      ruleId: 'mlflow.code_paths', cls: 'SANDBOX', severity: 'MEDIUM', cwe: 'CWE-829', anchor: 'code',
      title: 'MLflow model ships code that is imported on load',
      detail: `${file} declares bundled code (\`${JSON.stringify(codePaths).slice(0, 80)}\`) that MLflow puts on sys.path and imports when the model loads.`,
      remediation: 'Review and pin the bundled code; treat the model artifact as executable.',
      evidence: { codePaths, file },
    });
  }
  return out;
}

/* ─── Triton config.pbtxt ───────────────────────────────────────────────── */

function tritonFindings(text        , file        )                       {
  const out                       = [];
  const backend = /^\s*(?:backend|platform)\s*:\s*"python"/m.test(text);
  if (backend) {
    out.push({
      ruleId: 'triton.python_backend', cls: 'SANDBOX', severity: 'MEDIUM', cwe: 'CWE-94', anchor: '"python"',
      title: 'Triton model runs on the Python backend (model.py executes on load)',
      detail: `${file} selects \`backend: "python"\`: Triton imports the model directory's model.py into the server process when the model loads. Whoever can write that repository directory runs code in the inference server.`,
      remediation: 'Review and pin model.py, keep the model repository read-only to the server, and run Triton 25.07+ (Python-backend shared-memory fixes CVE-2025-23319/23320/23334).',
      evidence: { file },
    });
  }
  const envPath = /key\s*:\s*"EXECUTION_ENV_PATH"[\s\S]{0,200}?string_value\s*:\s*"([^"]+)"/.exec(text);
  if (envPath) {
    out.push({
      ruleId: 'triton.custom_execution_env', cls: 'BAD_DEPENDENCY', severity: 'MEDIUM', cwe: 'CWE-494', anchor: 'EXECUTION_ENV_PATH',
      title: `Triton Python model unpacks a custom environment (${envPath[1]})`,
      detail: `\`EXECUTION_ENV_PATH\` points at ${envPath[1]}, a packed Python environment the backend unpacks and runs the model inside - every package in it is code the server executes.`,
      remediation: 'Build the execution environment from a pinned, scanned lockfile and store it where only the build pipeline can write.',
      evidence: { path: envPath[1], file },
    });
  }
  return out;
}

/* ─── TorchServe config.properties ──────────────────────────────────────── */

function propsOf(text        )                         {
  const out                         = {};
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*([\w.]+)\s*[=:]\s*(.*?)\s*$/.exec(line);
    if (m && !line.trim().startsWith('#')) out[m[1]] = m[2];
  }
  return out;
}

function torchserveFindings(text        , file        )                       {
  const out                       = [];
  const p = propsOf(text);
  const exposed = (addr         ) => !!addr && /\/\/(?:0\.0\.0\.0|\[::\]|\*)(?::|$)/.test(addr);
  const mgmtOpen = exposed(p.management_address);
  // a wildcard is one that matches ANY HOST (`.*`, `https?://.*`, `file://.*`); `https://models.acme/.*` is scoped
  const allowedAny = !('allowed_urls' in p) || String(p.allowed_urls).split(/[|,]/).some((e) => /^\s*(?:\.\*|\^?(?:https?|http\(s\)\?|https\?|file|s3|gs)(?::\/\/|:\\\/\\\/)\.\*)\s*$/i.test(e));
  if (mgmtOpen) {
    out.push({
      ruleId: 'torchserve.management_exposed', cls: 'WEAK_AUTH', severity: allowedAny ? 'CRITICAL' : 'HIGH', cwe: 'CWE-306', anchor: 'management_address',
      title: `TorchServe management API listens on every interface${allowedAny ? ' and will register models from any URL' : ''}`,
      detail: `\`management_address=${p.management_address}\`${allowedAny ? ` with ${'allowed_urls' in p ? `allowed_urls=${p.allowed_urls}` : 'no allowed_urls (the default permits any http/file URL)'}` : ''}. Anyone who reaches the port can register a model archive - the ShellTorch chain (CVE-2023-43654, SSRF to RCE).`,
      remediation: 'Bind management_address to 127.0.0.1, set allowed_urls to your own model bucket only, and keep token authorization on.',
      evidence: { managementAddress: p.management_address, allowedUrls: p.allowed_urls ?? null, file },
    });
  } else if ('allowed_urls' in p && allowedAny) {
    out.push({
      ruleId: 'torchserve.allowed_urls_wildcard', cls: 'INSECURE_CONFIG', severity: 'MEDIUM', cwe: 'CWE-918', anchor: 'allowed_urls',
      title: 'TorchServe accepts model archives from any URL',
      detail: `\`allowed_urls=${p.allowed_urls}\` lets the management API fetch a .mar from anywhere - the SSRF half of ShellTorch.`,
      remediation: 'Restrict allowed_urls to the exact bucket/host your models come from.',
      evidence: { allowedUrls: p.allowed_urls, file },
    });
  }
  if (/^true$/i.test(p.disable_token_authorization ?? '')) {
    out.push({
      ruleId: 'torchserve.token_auth_disabled', cls: 'WEAK_AUTH', severity: 'HIGH', cwe: 'CWE-306', anchor: 'disable_token_authorization',
      title: 'TorchServe token authorization is disabled',
      detail: '`disable_token_authorization=true` removes the API key TorchServe requires on the inference and management APIs.',
      remediation: 'Remove the setting so token authorization stays on.',
      evidence: { file },
    });
  }
  if (exposed(p.inference_address) && !mgmtOpen) {
    out.push({
      ruleId: 'torchserve.inference_exposed', cls: 'INSECURE_CONFIG', severity: 'LOW', cwe: 'CWE-668', anchor: 'inference_address',
      title: 'TorchServe inference API listens on every interface',
      detail: `\`inference_address=${p.inference_address}\` - usually intended behind a load balancer; confirm the port is not reachable directly.`,
      remediation: 'Bind to a private interface and front it with an authenticating proxy.',
      evidence: { inferenceAddress: p.inference_address, file },
    });
  }
  return out;
}

/* ─── LiteLLM proxy config.yaml ─────────────────────────────────────────── */

const KNOWN_CALLBACKS = /^(?:langfuse|langsmith|lunary|helicone|datadog|prometheus|otel|opentelemetry|s3|gcs_bucket|azure_storage|sentry|slack|traceloop|openmeter|athina|braintrust|logfire|arize|arize_phoenix|galileo|opik|mlflow|wandb|posthog|supabase|dynamodb|generic|custom_callback_api|email|pagerduty|lago|greenscale|literalai|humanloop|argilla|bedrock_guardrails|aporia|lakera|presidio|hide_secrets|llamaguard)$/i;
const envRef = (v         ) => typeof v === 'string' && /^os\.environ\/|^\$\{?[A-Z_][A-Z0-9_]*\}?$|^os\.getenv/.test(v.trim());

function litellmFindings(doc     , file        )                       {
  const out                       = [];
  if (!isObj(doc)) return out;
  const settings = isObj(doc.litellm_settings) ? doc.litellm_settings : {};
  const general = isObj(doc.general_settings) ? doc.general_settings : {};
  const hooks           = [];
  for (const key of ['callbacks', 'success_callback', 'failure_callback', 'service_callback', 'post_call_rules', 'pre_call_hooks']) {
    const v = settings[key] ?? general[key];
    for (const c of Array.isArray(v) ? v : typeof v === 'string' ? [v] : []) if (typeof c === 'string' && !KNOWN_CALLBACKS.test(c) && /\./.test(c)) hooks.push(c);
  }
  for (const key of ['custom_auth', 'custom_sso', 'custom_key_generate']) if (typeof general[key] === 'string') hooks.push(general[key]);
  if (hooks.length) {
    const bad = hooks.find((h) => isDangerousCallable(h));
    out.push({
      ruleId: 'litellm.python_hook', cls: 'SANDBOX', severity: bad ? 'CRITICAL' : 'MEDIUM', cwe: 'CWE-94', anchor: (bad ?? hooks[0]).split('.')[0],
      title: bad ? `LiteLLM config wires a host-execution function as a callback (${bad})` : `LiteLLM config imports Python callbacks (${hooks[0]})`,
      detail: `${file} names ${hooks.slice(0, 3).join(', ')} as callbacks/hooks. The proxy imports and runs them on every request; a callback in the CONFIG is also invisible in the admin UI, so it persists after a compromise (CVE-2024-6825: a config callback as RCE).`,
      remediation: bad ? 'Remove it and treat the proxy as compromised.' : 'Confirm each module is your own reviewed code, pinned in the proxy image.',
      evidence: { hooks: hooks.slice(0, 8), file },
    });
  }
  if (typeof general.master_key === 'string' && general.master_key && !envRef(general.master_key)) {
    out.push({
      ruleId: 'litellm.literal_master_key', cls: 'SECRET_EXPOSURE', severity: 'HIGH', cwe: 'CWE-798', anchor: 'master_key',
      title: 'LiteLLM master key is written into the config',
      detail: `\`general_settings.master_key\` is a literal in ${file}. It is the admin credential for the proxy - every virtual key, budget and model route.`,
      remediation: 'Set it as `master_key: os.environ/LITELLM_MASTER_KEY` and rotate the exposed value.',
      evidence: { file },
    });
  }
  const literalKeys           = [];
  const plaintext           = [];
  for (const m of Array.isArray(doc.model_list) ? doc.model_list.slice(0, 500) : []) {
    const p = isObj(m?.litellm_params) ? m.litellm_params : {};
    for (const [k, v] of Object.entries(p)) {
      if (/(?:^|_)(?:api_key|secret|token|password|aws_secret_access_key)$/.test(k) && typeof v === 'string' && v.length >= 8 && !envRef(v)) literalKeys.push(`${m.model_name ?? '?'}.${k}`);
    }
    const apiBase = typeof p.api_base === 'string' ? p.api_base : '';
    if (/^http:\/\//i.test(apiBase) && !/\/\/(?:localhost|127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|host\.docker\.internal)/.test(apiBase)) plaintext.push(apiBase);
  }
  if (literalKeys.length) {
    out.push({
      ruleId: 'litellm.literal_provider_key', cls: 'SECRET_EXPOSURE', severity: 'HIGH', cwe: 'CWE-798', anchor: literalKeys[0].split('.').pop() ?? null,
      title: `LiteLLM config stores provider credentials as literals (${literalKeys.length})`,
      detail: `${literalKeys.slice(0, 4).join(', ')} are literal values, not \`os.environ/...\` references.`,
      remediation: 'Reference every provider key as os.environ/NAME and rotate the exposed ones.',
      evidence: { fields: literalKeys.slice(0, 10), file },
    });
  }
  if (plaintext.length) {
    out.push({
      ruleId: 'litellm.plaintext_api_base', cls: 'WEAK_AUTH', severity: 'MEDIUM', cwe: 'CWE-319', anchor: plaintext[0],
      title: `LiteLLM routes a model over plaintext HTTP (${plaintext[0]})`,
      detail: 'Prompts, completions and the provider key cross the network unencrypted.',
      remediation: 'Use an https api_base.',
      evidence: { apiBases: plaintext.slice(0, 5), file },
    });
  }
  return out;
}

/* ─── vLLM serve config ─────────────────────────────────────────────────── */

function vllmFindings(doc     , file        )                       {
  const out                       = [];
  if (!isObj(doc)) return out;
  const get = (k        ) => doc[k] ?? doc[k.replace(/-/g, '_')];
  if (get('trust-remote-code') === true || /^true$/i.test(String(get('trust-remote-code') ?? ''))) {
    out.push({
      ruleId: 'vllm.trust_remote_code', cls: 'SANDBOX', severity: 'HIGH', cwe: 'CWE-94', anchor: 'trust',
      title: 'vLLM serves with trust-remote-code on',
      detail: `${file} turns on trust-remote-code: the server imports the model repo's Python when it loads (and vLLM before 0.11.1 ran auto_map code even with it off, CVE-2025-66448).`,
      remediation: 'Turn it off unless the model needs it; pin the model to a reviewed revision and run vLLM 0.11.1+.',
      evidence: { file },
    });
  }
  const media = get('allowed-local-media-path');
  if (typeof media === 'string' && /^(?:\/|~|\/home\/[^/]+|\/Users\/[^/]+|[A-Za-z]:\\?)$/.test(media.trim())) {
    out.push({
      ruleId: 'vllm.broad_media_path', cls: 'OVER_PERMISSIONED', severity: 'HIGH', cwe: 'CWE-22', anchor: 'allowed-local-media-path',
      title: `vLLM lets requests read local media from ${media}`,
      detail: '`allowed-local-media-path` lets a request reference `file://` media under that path - set to a root or home directory, any client can read the host\'s files through a multimodal request.',
      remediation: 'Point it at a dedicated media directory, or remove it.',
      evidence: { path: media, file },
    });
  }
  const host = String(get('host') ?? '');
  if (/^(?:0\.0\.0\.0|::)$/.test(host) && !get('api-key')) {
    out.push({
      ruleId: 'vllm.open_bind', cls: 'WEAK_AUTH', severity: 'MEDIUM', cwe: 'CWE-306', anchor: 'host',
      title: 'vLLM listens on every interface without an API key',
      detail: `host ${host} and no api-key: anyone who reaches the port can run inference - and, with LoRA runtime updating enabled, load adapters.`,
      remediation: 'Set api-key (from an environment variable) or bind to 127.0.0.1 behind an authenticating proxy.',
      evidence: { host, file },
    });
  }
  return out;
}

/* ─── BentoML bentofile.yaml ────────────────────────────────────────────── */

const SHELL_META_RE = /[;&|`$\n\r]|\$\(/;

function bentoFindings(doc     , file        )                       {
  const out                       = [];
  if (!isObj(doc)) return out;
  const docker = isObj(doc.docker) ? doc.docker : {};
  const pkgs = (Array.isArray(docker.system_packages) ? docker.system_packages : []).filter((p         ) => typeof p === 'string' && SHELL_META_RE.test(p));
  const envs = (Array.isArray(doc.envs) ? doc.envs : []).map((e     ) => (isObj(e) ? e.name : e)).filter((n         ) => typeof n === 'string' && SHELL_META_RE.test(n));
  if (pkgs.length || envs.length) {
    out.push({
      ruleId: 'bentoml.build_injection', cls: 'SANDBOX', severity: 'HIGH', cwe: 'CWE-78', anchor: (pkgs[0] ?? envs[0]).slice(0, 30),
      title: 'BentoML build config injects shell into the generated Dockerfile',
      detail: `${pkgs.length ? `docker.system_packages entry ${JSON.stringify(pkgs[0])}` : `envs name ${JSON.stringify(envs[0])}`} carries shell metacharacters; BentoML writes these into the image's build commands (CVE-2026-33744 / CVE-2026-44346, fixed 1.4.39), so building the bento runs them.`,
      remediation: 'Use plain package/variable names and upgrade BentoML to 1.4.39+.',
      evidence: { systemPackages: pkgs.slice(0, 5), envs: envs.slice(0, 5), file },
    });
  }
  const python = isObj(doc.python) ? doc.python : {};
  const idx = [python.index_url, ...(Array.isArray(python.extra_index_url) ? python.extra_index_url : [python.extra_index_url])].filter((x) => typeof x === 'string');
  const plain = idx.find((u        ) => /^http:\/\//i.test(u));
  if (plain || python.extra_index_url) {
    out.push({
      ruleId: 'bentoml.package_index', cls: 'BAD_DEPENDENCY', severity: plain ? 'HIGH' : 'MEDIUM', cwe: plain ? 'CWE-319' : 'CWE-427', anchor: plain ?? 'extra_index_url',
      title: plain ? `BentoML installs Python packages over plaintext HTTP (${plain})` : 'BentoML resolves packages from an extra index (dependency confusion)',
      detail: plain ? 'Every package in the image crosses the network unencrypted.' : 'With two indexes pip takes the highest version from either - a public package can shadow a private name.',
      remediation: plain ? 'Use an https index.' : 'Use a single index that proxies PyPI, or pin with hashes.',
      evidence: { indexes: idx, file },
    });
  }
  if (typeof docker.setup_script === 'string') {
    out.push({
      ruleId: 'bentoml.setup_script', cls: 'SANDBOX', severity: 'LOW', cwe: 'CWE-78', anchor: 'setup_script',
      title: `BentoML runs a setup script while building the image (${docker.setup_script})`,
      detail: 'The script executes as root during the image build; it is part of the model\'s supply chain.',
      remediation: 'Keep the script in the reviewed repository and pin anything it downloads.',
      evidence: { script: docker.setup_script, file },
    });
  }
  return out;
}

/* ─── YAML python tags (any model yaml) ─────────────────────────────────── */

function yamlTagFindings(text        , file        )                       {
  const m = /!!python\/(?:object(?:\/apply|\/new)?|name|module)\s*:?\s*([\w.]*)/.exec(text);
  if (!m) return [];
  return [{
    ruleId: 'model_config.yaml_python_tag', cls: 'SANDBOX', severity: 'CRITICAL', cwe: 'CWE-502', anchor: '!!python/',
    title: `Model config carries a Python object tag (${m[0].slice(0, 60)})`,
    detail: `\`${m[0]}\` in ${file} makes an unsafe YAML loader import and call a Python object - loading the config IS running code (the ms-swift --run_config class, CVE-2025-50460).`,
    remediation: 'Remove the tag, and load configs only with yaml.safe_load.',
    evidence: { tag: m[0].slice(0, 80), file },
  }];
}

/* ─── entry point ───────────────────────────────────────────────────────── */

function parseDoc(format                   , path        , text        )      {
  if (format === 'triton' || format === 'torchserve') return null;
  if (/\.ya?ml$/i.test(path) || format === 'mlflow') return parseYaml(text);
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

/** Every finding a model / serving config earns. `format` is detected from the path + text when omitted. */
export function gradeModelConfig(path        , text                           , format                           )                       {
  const t = String(text ?? '');
  const fmt = format ?? modelConfigFormat(path, t);
  if (!fmt || !t.trim()) return [];
  const file = base(path) || path;
  const doc = parseDoc(fmt, path, t);
  const out                       = [];
  switch (fmt) {
    case 'hf-config': out.push(...hfConfigFindings(doc, file)); break;
    case 'tokenizer': out.push(...tokenizerFindings(doc, file), ...targetFindings(doc, file, { inWeightsConfig: true })); break;
    case 'peft-adapter': out.push(...peftFindings(doc, file), ...targetFindings(doc, file, { inWeightsConfig: true })); break;
    case 'diffusers-index': out.push(...diffusersFindings(doc, file)); break;
    case 'st-modules': out.push(...stModulesFindings(doc, file)); break;
    case 'mlflow': out.push(...mlflowFindings(doc, file)); break;
    case 'triton': out.push(...tritonFindings(t, file)); break;
    case 'torchserve': out.push(...torchserveFindings(t, file)); break;
    case 'litellm': out.push(...litellmFindings(doc, file)); break;
    case 'vllm': out.push(...vllmFindings(doc, file)); break;
    case 'bentoml': out.push(...bentoFindings(doc, file)); break;
    case 'hydra-yaml': out.push(...targetFindings(doc, file, { inWeightsConfig: /model_config|hparams|nemo/i.test(path) })); break;
  }
  if (/\.ya?ml$/i.test(path) || fmt === 'mlflow') out.push(...yamlTagFindings(t, file));
  return out;
}

/** True when a config.json carries a signal only this module grades (so the detector claims it as MODEL_CONFIG). */
export function hasModelConfigSignal(path        , text                           )          {
  const fmt = modelConfigFormat(path, text);
  if (!fmt) return false;
  if (fmt !== 'hf-config' && fmt !== 'tokenizer') return true;
  return gradeModelConfig(path, text, fmt).length > 0;
}
