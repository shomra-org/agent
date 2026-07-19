/**
 * Local SAST rule engine for AI-artifact source code — a dependency-free port of
 * the server-side engine, so the CLI can catch the same AI-vulnerability shapes
 * ON-MACHINE (offline, pre-commit, in the IDE) that the model scan and workspace
 * scan catch server-side. Nothing here is executed.
 *
 * Three analysis tiers, worst-first, tuned for low false positives:
 *
 *   1. Pattern rules (line/logical-line oriented regexes) over three languages —
 *      • Python: eval/exec/os.system/subprocess, pickle/torch.load/cloudpickle/
 *        jsonpickle deserialization, trust_remote_code, torch.hub/PackageImporter
 *        remote code, weights_only=False, Keras safe_mode=False Lambda RCE,
 *        pandas.read_pickle / mlflow load, unsafe YAML, RAG/FAISS unsafe deser,
 *        __reduce__ gadgets, the agentic code-executing frameworks (LangChain
 *        PythonREPL/PALChain, LlamaIndex PandasQueryEngine, smolagents CodeAgent /
 *        LocalPythonExecutor, AutoGen local code_execution, load_tools python_repl),
 *        LangChain serialized-chain loads, Gradio share=True exposure, hardcoded
 *        AI-provider keys, network egress, dynamic imports, decode-and-run, secrets.
 *      • JS/TS: eval/new Function/vm/string-setTimeout, child_process, decode-and-run
 *        packers, dynamic require/import, network egress, hardcoded AI keys.
 *      • config.json / tokenizer_config.json: auto_map / custom_pipeline / declared
 *        trust_remote_code → remote-code-under-load.
 *
 *   2. Heuristic LLM-output propagation tier (NOT true dataflow) — marks a
 *      variable assigned from an LLM call (`.generate` / `.invoke` /
 *      `.completions.create` …) as tainted, propagates by NAME SUBSTRING across
 *      simple assignments, and raises an `*.llm_output_to_sink` finding when a
 *      tainted name appears in a code-execution sink's arguments. Surfaces the
 *      prompt-injection → RCE shape single-sink matching misses, but it is a
 *      low-confidence heuristic, not analysis: no scope, no reassignment/kill, no
 *      sanitizer awareness, no interprocedural tracking — it can over- and
 *      under-report. Findings are HIGH at low confidence with hedged wording.
 *
 *   3. Cross-signal chain tier — synthesises a finding when two independently
 *      suspicious signals co-occur in one file: encoded-payload + code-exec
 *      (`chain.decode_exec`), or remote-code loading + network egress
 *      (`chain.remote_code_egress`). Conjunctions only, so no added false positives.
 *
 * Findings carry a stable dotted rule id, the matched SINK, an optional SOURCE, a
 * CWE, a category, a 0–1 confidence, the FILE + physical LINE and a context
 * SNIPPET — the exact shape shomra.mjs folds into a gate result. The rule bodies
 * mirror the server engine; drift only costs recall on the local floor, and the
 * server remains the full check.
 */

const MAX_SNIPPET = 400;
const CONTEXT_RADIUS = 3;
/**
 * Cap on how many physical lines one logical statement may absorb. Bounds the
 * regex work and stops a single unbalanced-bracket line (or a minified blob)
 * from swallowing the rest of the file into one giant unit.
 */
const MAX_JOIN_LINES = 40;

// ── Python rules ──────────────────────────────────────────────────
const PY_RULES = [
  {
    id: 'python.dangerous_sinks',
    title: 'Dangerous code-execution sink',
    severity: 'CRITICAL',
    category: 'code-exec',
    confidence: 0.85,
    re: /(?<![.\w])(eval|exec|compile)\s*\(|\bos\.(system|popen|exec[lv]?[pe]*)\s*\(|\bsubprocess\.(run|call|check_output|check_call|Popen)\s*\(|(?<![.\w])__import__\s*\(|(?<![.\w])getattr\s*\(\s*__builtins__/,
    sink: (m) => m[0].replace(/\s*\($/, '').trim(),
    source: 'model load / forward()',
    message: 'Model code invokes an arbitrary code-execution primitive. Under trust_remote_code this runs in the host process the moment the model is imported.',
    remediation: 'Remove the eval/exec/os.system/subprocess call. Load this model only after reviewing the pinned revision; never with trust_remote_code=True from an untrusted publisher.',
    cwe: 'CWE-94',
  },
  {
    id: 'python.pickle_deserialization',
    title: 'Unsafe deserialization',
    severity: 'CRITICAL',
    category: 'deserialization',
    confidence: 0.9,
    // Pickle-backed loaders across the ML stack: raw pickle/dill/cloudpickle/
    // jsonpickle, torch.load, joblib/skops, numpy allow_pickle, yaml.load without a
    // safe Loader, shelve, pandas.read_pickle, mlflow.*.load_model. All run
    // __reduce__ / arbitrary code on a crafted file the moment they load.
    re: /\b(pickle|cpickle|dill|_pickle|cloudpickle)\.(loads?|Unpickler)\s*\(|\bjsonpickle\.(decode|loads)\s*\(|\bmarshal\.loads?\s*\(|\btorch\.(load|jit\.load)\s*\(|\byaml\.(unsafe_load|load\s*\((?![^)]*Loader\s*=\s*yaml\.(Safe|Full)Loader))|\bjoblib\.load\s*\(|\bskops\.io\.load\s*\(|\bshelve\.open\s*\(|\bnumpy\.load\s*\([^)]*allow_pickle\s*=\s*True|\b(pandas|pd)\.read_pickle\s*\(|\bmlflow\.[\w.]+\.load_model\s*\(/,
    sink: (m) => m[0].replace(/\s*\($/, '').trim(),
    source: 'weight / config file',
    message: 'Deserializes data with a pickle-backed loader. A crafted file runs arbitrary code via __reduce__ on load — the primary model-hub malware vector.',
    remediation: 'Load weights from safetensors (use_safetensors=True). For YAML use yaml.safe_load; for numpy set allow_pickle=False; avoid torch.load / cloudpickle / pandas.read_pickle / mlflow.load_model on untrusted files.',
    cwe: 'CWE-502',
  },
  {
    id: 'python.trust_remote_code',
    title: 'Model loaded with trust_remote_code',
    severity: 'CRITICAL',
    category: 'remote-code',
    confidence: 0.95,
    // codeOnly: keyword appears in docstrings / log warnings / usage examples
    // (e.g. Falcon's "load without the trust_remote_code=True argument").
    codeOnly: true,
    re: /trust_remote_code\s*=\s*True/,
    sink: () => 'trust_remote_code=True',
    source: 'model repository',
    message: 'Loads a model/tokenizer/embedder with trust_remote_code=True, which imports and runs code shipped in the model repo inside the host process before any weights load — an instant RCE if the publisher, or a later silent revision, is malicious.',
    remediation: 'Remove trust_remote_code=True. Prefer a model with native transformers support, or pin revision= to a specific reviewed commit hash and read the custom modeling code first.',
    cwe: 'CWE-94',
  },
  {
    id: 'python.dataset_remote_code',
    title: 'Dataset loaded with trust_remote_code',
    severity: 'CRITICAL',
    category: 'remote-code',
    confidence: 0.9,
    codeOnly: true,
    // datasets.load_dataset(..., trust_remote_code=True) runs the dataset's own
    // Python loading script — a DISTINCT RCE vector from model trust_remote_code.
    re: /\bload_dataset\s*\((?=[^)]*trust_remote_code\s*=\s*True)/,
    sink: () => 'load_dataset(trust_remote_code=True)',
    source: 'dataset repository',
    message: 'Loads a Hugging Face dataset with trust_remote_code=True, which imports and runs the dataset\'s Python loading script in the host process — arbitrary code execution from the dataset publisher.',
    remediation: 'Remove trust_remote_code=True. Use a non-script dataset format (Parquet/Arrow/CSV/JSON), or pin revision= to a reviewed commit and read the loading script first.',
    cwe: 'CWE-94',
  },
  {
    id: 'python.native_code_load',
    title: 'Loads a native library (ctypes)',
    severity: 'HIGH',
    category: 'code-exec',
    confidence: 0.85,
    re: /\bctypes\.(CDLL|WinDLL|OleDLL|PyDLL|cdll|windll|oledll)\b|\bcdll\.LoadLibrary\s*\(|\bwindll\.LoadLibrary\s*\(/,
    sink: (m) => m[0].replace(/\s*\($/, '').trim(),
    source: 'native library',
    message: 'Loads a native/shared library via ctypes. Model code has no reason to dlopen libc or an arbitrary .so/.dll — it is an execution primitive (e.g. ctypes.CDLL("libc.so.6").system(cmd)).',
    remediation: 'Remove the ctypes native-library load from model/loader code. Treat any model that dlopens libraries on load as hostile.',
    cwe: 'CWE-94',
  },
  {
    id: 'python.dynamic_file_exec',
    title: 'Loads and executes a Python file at runtime',
    severity: 'HIGH',
    category: 'code-exec',
    confidence: 0.85,
    re: /\bSourceFileLoader\s*\(|\bspec_from_file_location\s*\(|\bimp\.load_source\s*\(|\bexec_module\s*\(/,
    sink: (m) => m[0].replace(/\s*\($/, '').trim(),
    source: 'file path',
    message: 'Imports and executes a Python file from a path at runtime (SourceFileLoader / spec_from_file_location / imp.load_source). This runs code that is not statically visible as an import — a common way to hide an execution path.',
    remediation: 'Remove runtime file-based module loading from model code. Import only reviewed, statically-visible modules.',
    cwe: 'CWE-94',
  },
  {
    id: 'python.torch_remote_code',
    title: 'Loads/executes remote or native code via torch',
    severity: 'CRITICAL',
    category: 'remote-code',
    confidence: 0.9,
    re: /\btorch\.hub\.load\s*\(|\btorch\.hub\.load_state_dict_from_url\s*\(|\btorch\.package\.PackageImporter\s*\(|\btorch\.classes\.load_library\s*\(/,
    sink: (m) => m[0].replace(/\s*\($/, '').trim(),
    source: 'remote repo / packaged code',
    message: 'Fetches and executes code that is not in this repository (torch.hub.load runs a remote hubconf.py; load_state_dict_from_url pulls a pickle; PackageImporter / load_library run packaged or native code) — an instant RCE at load time.',
    remediation: 'Do not torch.hub.load untrusted repos (and never with trust_repo=True on an unreviewed source). Load a local, reviewed safetensors checkpoint instead.',
    cwe: 'CWE-494',
  },
  {
    id: 'python.weights_only_false',
    title: 'torch.load with weights_only=False',
    severity: 'CRITICAL',
    category: 'deserialization',
    confidence: 0.95,
    re: /\btorch\.load\s*\([^)]*weights_only\s*=\s*False/,
    sink: () => 'torch.load(..., weights_only=False)',
    source: 'weight file',
    message: 'torch.load is called with weights_only=False, which turns the safe (default since torch 2.6) tensor-only loader back into the full pickle unpickler — a crafted checkpoint then runs arbitrary code via __reduce__ on load.',
    remediation: 'Remove weights_only=False (let it default to True), or load from safetensors. Only ever disable it for a checkpoint you built yourself.',
    cwe: 'CWE-502',
  },
  {
    id: 'python.keras_unsafe_load',
    title: 'Keras load with safe_mode disabled',
    severity: 'HIGH',
    category: 'deserialization',
    confidence: 0.85,
    re: /\bsafe_mode\s*=\s*False/,
    sink: () => 'safe_mode=False',
    source: 'model file',
    message: 'A Keras/TensorFlow model is loaded with safe_mode=False, which allows deserialization of Lambda layers — arbitrary Python bytecode that executes the moment the model loads (CVE-2024-3660 / CVE-2025-1550 class).',
    remediation: 'Remove safe_mode=False. Load only models you trust; a Lambda layer in an untrusted model is remote code execution regardless of format (.h5 ignores safe_mode entirely).',
    cwe: 'CWE-502',
  },
  {
    id: 'python.langchain_code_exec',
    title: 'LLM-driven code-execution component',
    severity: 'HIGH',
    category: 'agentic',
    confidence: 0.85,
    // Agent-framework components that run LLM-generated code (exec/eval on model
    // output). LangChain (PythonREPL, PAL/CPAL, LLMMathChain), LlamaIndex
    // (PandasQueryEngine, PandasInstructionParser, CodeInterpreterToolSpec),
    // smolagents (CodeAgent, LocalPythonExecutor), plus load_tools() wiring a
    // python_repl/terminal/shell tool. Distinctive names → near-zero FP; any of
    // them reached by untrusted model output is RCE in the agent host.
    re: /\b(PythonREPL|PythonREPLTool|PythonAstREPLTool|PALChain|CPALChain|LLMMathChain|create_pandas_dataframe_agent|create_spark_dataframe_agent|create_csv_agent|PandasQueryEngine|PandasInstructionParser|CodeInterpreterToolSpec|CodeAgent|LocalPythonExecutor|local_python_executor|PythonInterpreterTool)\b|\bload_tools\s*\([^)]*['"](python_repl|terminal|shell|bash)/,
    sink: (m) => m[0].trim(),
    source: 'LLM output',
    message: 'Uses an agent-framework component that executes LLM-generated code (exec/eval on model output). If the model can be steered (prompt injection), this is remote code execution in the agent host (CVE-2023-29374 / CVE-2024-4181 class).',
    remediation: 'Avoid code-executing chains/tools on untrusted input. If unavoidable, run them in a locked-down sandbox with no host/network access and a strict output validator.',
    cwe: 'CWE-94',
  },
  {
    id: 'python.autogen_local_exec',
    title: 'Agent executes LLM-written code locally',
    severity: 'HIGH',
    category: 'agentic',
    confidence: 0.75,
    // AutoGen / ag2 executes code the LLM writes. A dict code_execution_config
    // (rather than False) enables it; use_docker=False forces it to run on the
    // host instead of an isolated container — LLM-authored code as host RCE.
    re: /code_execution_config\s*=\s*\{|use_docker\s*=\s*False/,
    sink: (m) => m[0].replace(/\s*=\s*\{$/, '').trim(),
    source: 'LLM output',
    message: 'An AutoGen-style agent is configured to execute LLM-written code on the host (a dict code_execution_config / use_docker=False). Any prompt-injected instruction the model follows becomes code execution in the agent process.',
    remediation: 'Set code_execution_config=False, or require use_docker=True (an isolated container) with no host mounts and a locked-down image. Never run model-authored code directly on the host.',
    cwe: 'CWE-94',
  },
  {
    id: 'python.langchain_serialized_load',
    title: 'Loads a serialized chain / prompt / agent',
    severity: 'HIGH',
    category: 'deserialization',
    confidence: 0.75,
    // LangChain load_chain/load_prompt/load_agent deserialize a JSON/YAML config
    // that can instantiate arbitrary classes; hub.pull fetches a remote prompt/
    // chain object. A poisoned artifact becomes code at construction time.
    re: /\b(load_chain|load_prompt|load_agent)\s*\(|\bhub\.pull\s*\(/,
    sink: (m) => m[0].replace(/\s*\($/, '').trim(),
    source: 'serialized chain / hub',
    message: 'Deserializes a LangChain chain/prompt/agent from a file or the hub. The serialized config can name arbitrary classes to construct — a poisoned artifact is code execution when the object is built.',
    remediation: 'Build chains in code from reviewed source, not from an untrusted serialized artifact; if you must load one, pin and review it and never load from a user-supplied path/URL.',
    cwe: 'CWE-502',
  },
  {
    id: 'python.rag_unsafe_deser',
    title: 'Unsafe vector-store / RAG deserialization',
    severity: 'CRITICAL',
    category: 'deserialization',
    confidence: 0.9,
    re: /allow_dangerous_deserialization\s*=\s*True|\bFAISS\.load_local\s*\(|\b(pickle|joblib)\.load\s*\([^)]*(index|faiss|embedding|vector|chroma)/i,
    sink: (m) => m[0].replace(/\s*\($/, '').trim(),
    source: 'vector store / embedding index',
    message: 'Loads a RAG vector store or embedding index through a pickle-backed path (allow_dangerous_deserialization / FAISS.load_local / a pickled index). A poisoned index file executes arbitrary code the moment it is loaded — the embedding-store supply-chain vector.',
    remediation: 'Never set allow_dangerous_deserialization=True on an index you did not build. Rebuild the vector store from source documents in your own environment, or use a non-pickle store format.',
    cwe: 'CWE-502',
  },
  {
    id: 'python.mcp_client',
    title: 'MCP client integration (untrusted tool-output ingress)',
    // LOW capability twin of js.mcp_client: importing the MCP SDK client surface
    // says this file acts as an MCP host that feeds server tool output to a model.
    severity: 'LOW',
    category: 'agentic',
    confidence: 0.55,
    // Precise: `mcp.client.*` and `from mcp.client…import` are unambiguous;
    // `from mcp import` only counts WITH ClientSession (excludes server-authoring
    // imports); bare ClientSession( is NOT matched (aiohttp.ClientSession FP).
    re: /\bfrom\s+mcp\.client[\w.]*\s+import\b|\bimport\s+mcp\.client\b|\bmcp\.client\.\w+|\bfrom\s+mcp\s+import\b[^\n]*\bClientSession\b/,
    codeOnly: true,
    sink: (m) => m[0].trim(),
    source: 'MCP server tool output',
    message: 'Acts as an MCP client/host: opens a ClientSession to MCP servers and passes their tool descriptions and results back to a model. Every server it reaches is an untrusted-input ingress — a poisoned tool description or result can hijack the agent (prompt injection / tool poisoning).',
    remediation: 'Pin exactly which MCP servers this client may connect to and run each through governance before trusting it. Treat all server output as untrusted data, never instructions, and screen it (runtime firewall) before it reaches the model.',
    cwe: 'CWE-829',
  },
  {
    id: 'python.reduce_payload',
    title: 'Custom __reduce__ (pickle RCE gadget)',
    severity: 'CRITICAL',
    category: 'deserialization',
    confidence: 0.8,
    re: /def\s+__reduce__\s*\(|def\s+__reduce_ex__\s*\(|def\s+__setstate__\s*\(/,
    sink: (m) => m[0].replace(/^def\s+/, '').replace(/\s*\($/, '').trim(),
    message: 'Defines a pickle reduction hook. These execute on unpickling and are the classic gadget used to hide code-exec inside a serialized model object.',
    remediation: 'Verify why the class needs custom pickling. Do not unpickle objects from this repo; prefer safetensors serialization which has no code path.',
    cwe: 'CWE-502',
  },
  {
    id: 'python.network_egress',
    title: 'Network egress from model code',
    severity: 'HIGH',
    category: 'egress',
    confidence: 0.6,
    re: /\b(requests|httpx)\.(get|post|put|request)\s*\(|\burllib\.request\.(urlopen|urlretrieve)\s*\(|\bsocket\.(socket|create_connection)\s*\(|\baiohttp\.ClientSession\s*\(/,
    sink: (m) => m[0].replace(/\s*\($/, '').trim(),
    source: 'network',
    message: 'Model code opens a network connection. Legitimate modeling/tokenizer code has no reason to phone out — this is the exfiltration / second-stage-download shape.',
    remediation: 'Review the destination and payload. Model inference code should never make outbound requests; treat this model as hostile until proven otherwise.',
    cwe: 'CWE-913',
  },
  {
    id: 'python.dynamic_import',
    title: 'Dynamic / obfuscated import',
    severity: 'HIGH',
    category: 'obfuscation',
    confidence: 0.7,
    re: /\bimportlib\.import_module\s*\(|\b__import__\s*\(\s*['"]?\s*(os|subprocess|socket|base64|marshal|ctypes)|\bexec\s*\(\s*(base64|bytes|marshal|codecs)/,
    sink: (m) => m[0].trim(),
    message: 'Imports or executes a module chosen at runtime, often to hide os/subprocess/socket usage from a quick read.',
    remediation: 'Resolve what is imported and why. Obfuscated dynamic imports in model code are a strong malware tell.',
    cwe: 'CWE-94',
  },
  {
    id: 'python.encoded_payload',
    title: 'Encoded blob decode',
    // LOW on its own: base64/hex decode is ubiquitous & benign in ML (tokenizer
    // vocabs, quant kernels). The dangerous decode→exec case is elevated to
    // CRITICAL by chain.decode_exec. marshal.loads moved to pickle_deserialization.
    severity: 'LOW',
    category: 'obfuscation',
    confidence: 0.5,
    re: /\b(base64|codecs|binascii)\.(b64decode|decode|unhexlify)\s*\(|bytes\.fromhex\s*\(/,
    sink: (m) => m[0].replace(/\s*\($/, '').trim(),
    message: 'Decodes an encoded blob. Benign on its own (common in tokenizers/quantization), but the "decode then run it" packer combines this with eval/exec — see any decode-and-run chain finding on this file.',
    remediation: 'If this decode feeds eval/exec/import, decode the blob offline and inspect it. A lone decode of vocab/kernel data is expected.',
    cwe: 'CWE-506',
  },
  {
    id: 'python.gradio_public_share',
    title: 'Model UI exposed via public share tunnel',
    severity: 'MEDIUM',
    category: 'exposure',
    confidence: 0.8,
    re: /\.launch\s*\([^)]*share\s*=\s*True|\.queue\s*\([^)]*\)\.launch\s*\([^)]*share\s*=\s*True/,
    sink: () => 'launch(share=True)',
    message: 'Launches a Gradio/model UI with share=True, publishing a public tunnel URL to a locally-running model — anyone with the link can drive inference (and any tools wired to it) with no auth.',
    remediation: 'Remove share=True for anything beyond a throwaway demo. Bind to localhost or put the app behind authenticated ingress; never expose a tool-enabled agent this way.',
    cwe: 'CWE-668',
  },
  {
    id: 'python.hardcoded_ai_key',
    title: 'Hardcoded AI-provider API key',
    severity: 'MEDIUM',
    category: 'secret',
    confidence: 0.85,
    // Provider key prefixes embedded as string literals: Anthropic (sk-ant-),
    // OpenAI (sk-), HuggingFace (hf_), Google (AIza), Groq (gsk_).
    re: /['"](sk-ant-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{20,}|hf_[A-Za-z0-9]{20,}|AIza[A-Za-z0-9_-]{20,}|gsk_[A-Za-z0-9]{20,})['"]/,
    sink: (m) => m[1].slice(0, 12) + '…',
    source: 'source literal',
    message: 'An AI-provider API key is hardcoded as a string literal. Anyone with read access to this repo can drain the account; committed keys are scraped within minutes.',
    remediation: 'Remove the literal and load the key from an environment variable / secret manager at runtime. Rotate the exposed key immediately.',
    cwe: 'CWE-798',
  },
  {
    id: 'python.env_exfil',
    title: 'Reads environment / secrets',
    severity: 'MEDIUM',
    category: 'secret',
    confidence: 0.5,
    re: /\bos\.environ\b|\bos\.getenv\s*\(|\bParameterStore|\bboto3\.client\s*\(\s*['"]s(ts|ecretsmanager)/,
    sink: (m) => m[0].trim(),
    source: 'process environment',
    message: 'Reads environment variables or a secrets store. Paired with network egress this is credential exfiltration.',
    remediation: 'Confirm the code has a legitimate need for the variable; model inference code generally should not read the environment.',
    cwe: 'CWE-200',
  },
];

// ── JavaScript / TypeScript rules ─────────────────────────────────
const JS_RULES = [
  {
    id: 'js.code_exec',
    title: 'Dynamic code execution',
    severity: 'CRITICAL',
    category: 'code-exec',
    confidence: 0.85,
    re: /(?<![.\w])eval\s*\(|\bnew\s+Function\s*\(|\bvm\.(runInContext|runInNewContext|runInThisContext|compileFunction)\s*\(|\bnew\s+vm\.Script\s*\(|\b(setTimeout|setInterval)\s*\(\s*['"`]/,
    sink: (m) => m[0].replace(/\s*\($/, '').replace(/\s*\(\s*['"`]$/, '').trim(),
    source: 'tool input / model output',
    message: 'Runs a string as code via eval / new Function / vm / a string-valued setTimeout|setInterval. In an MCP server or agent tool this turns any attacker-influenced string into host code execution.',
    remediation: 'Never eval strings. Parse structured input explicitly (JSON.parse) and dispatch on a fixed allowlist of handlers.',
    cwe: 'CWE-94',
  },
  {
    id: 'js.command_exec',
    title: 'Shell / process execution',
    severity: 'CRITICAL',
    category: 'code-exec',
    confidence: 0.8,
    re: /\bchild_process\b|require\(\s*['"]child_process['"]\s*\)|\bfrom\s+['"]child_process['"]|\b(execSync|execFileSync|spawnSync|execFile)\s*\(/,
    sink: (m) => m[0].trim(),
    source: 'tool input / model output',
    message: 'Spawns a shell or child process. If any argument derives from tool input or model output this is command injection / RCE in the agent host.',
    remediation: 'Avoid shelling out. If unavoidable, use execFile with a fixed binary and an argument array (never a shell string), and validate every argument.',
    cwe: 'CWE-78',
  },
  {
    id: 'js.mcp_client',
    title: 'MCP client integration (untrusted tool-output ingress)',
    // LOW capability signal: the /client SDK entrypoint or a *ClientTransport says
    // this file acts as an MCP host — it connects to servers and feeds their tool
    // output to a model. That is the toxic-flow ingress; on its own it is a lead.
    severity: 'LOW',
    category: 'agentic',
    confidence: 0.55,
    // /client subpath + transport class names are unambiguous. `new Client(` is NOT
    // matched — too many libs export a generic Client. Not codeOnly: the /client
    // import path lives inside a require()/import string.
    re: /@modelcontextprotocol\/sdk\/client|\b(StdioClientTransport|SSEClientTransport|StreamableHTTPClientTransport|WebSocketClientTransport)\b/,
    sink: (m) => m[0].trim(),
    source: 'MCP server tool output',
    message: 'Acts as an MCP client/host: connects to MCP servers and passes their tool descriptions and results back to a model. Every server it reaches is an untrusted-input ingress — a poisoned tool description or result can hijack the agent (prompt injection / tool poisoning).',
    remediation: 'Pin exactly which MCP servers this client may connect to and run each through governance before trusting it. Treat all server output as untrusted data, never instructions, and screen it (runtime firewall) before it reaches the model.',
    cwe: 'CWE-829',
  },
  {
    id: 'js.decode_and_run',
    title: 'Encoded payload decode-and-run',
    severity: 'CRITICAL',
    category: 'obfuscation',
    confidence: 0.85,
    re: /(?<![.\w])(eval|Function)\s*\(\s*(atob|unescape|decodeURIComponent|Buffer\.from)\b/,
    sink: (m) => m[0].replace(/\s*$/, '').trim(),
    message: 'Decodes an encoded string and immediately executes it — the packer pattern used to hide malicious code inside an otherwise innocuous-looking tool.',
    remediation: 'Decode the blob offline and inspect it. Remove any decode-and-execute path from shipped tool code.',
    cwe: 'CWE-506',
  },
  {
    id: 'js.dynamic_require',
    title: 'Dynamic / obfuscated module load',
    severity: 'HIGH',
    category: 'obfuscation',
    confidence: 0.6,
    re: /(?<![.\w])require\s*\(\s*[^'"\s)]|(?<![.\w])import\s*\(\s*[^'"\s)]/,
    sink: (m) => m[0].trim(),
    message: 'Loads a module chosen at runtime rather than a string literal, often to conceal which dangerous module is imported.',
    remediation: 'Import modules by string literal so the dependency is statically reviewable; remove runtime-computed requires.',
    cwe: 'CWE-829',
  },
  {
    id: 'js.network_egress',
    title: 'Network egress from tool code',
    severity: 'HIGH',
    category: 'egress',
    confidence: 0.6,
    re: /\baxios\s*\.\s*(get|post|put|request)\s*\(|\bhttps?\.request\s*\(|\bnet\.(connect|createConnection)\s*\(|\bnew\s+WebSocket\s*\(|require\(\s*['"](node-fetch|got|undici|axios)['"]/,
    sink: (m) => m[0].replace(/\s*\($/, '').trim(),
    source: 'network',
    message: 'Opens an outbound connection from tool code. Paired with reads of secrets or files this is the exfiltration / second-stage-download shape.',
    remediation: 'Confirm the destination is expected and necessary; agent tools should not phone out to arbitrary hosts.',
    cwe: 'CWE-913',
  },
  {
    id: 'js.hardcoded_ai_key',
    title: 'Hardcoded AI-provider API key',
    severity: 'MEDIUM',
    category: 'secret',
    confidence: 0.85,
    re: /['"](sk-ant-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{20,}|hf_[A-Za-z0-9]{20,}|AIza[A-Za-z0-9_-]{20,}|gsk_[A-Za-z0-9]{20,})['"]/,
    sink: (m) => m[1].slice(0, 12) + '…',
    source: 'source literal',
    message: 'An AI-provider API key is hardcoded as a string literal. Anyone with read access to this repo can drain the account; committed keys are scraped within minutes.',
    remediation: 'Remove the literal and load the key from an environment variable / secret manager at runtime. Rotate the exposed key immediately.',
    cwe: 'CWE-798',
  },
];

// ── config.json rules (auto_map → trust_remote_code target) ───────
const CONFIG_RULES = [
  {
    id: 'json.automodel_usage',
    // MEDIUM, not HIGH: capability/posture fact (ships trust_remote_code code) —
    // true of every legit custom model, so HIGH is alert fatigue. A real sink in
    // the routed module is elevated to CRITICAL by chain.config_module_rce.
    title: 'AutoModel bound to repo-shipped code (trust_remote_code)',
    severity: 'MEDIUM',
    category: 'remote-code',
    confidence: 0.8,
    re: /"(AutoModel[A-Za-z]*|AutoConfig)"\s*:\s*"([^"]+)"/,
    sink: (m) => `auto_map.${m[1]}`,
    message: 'config.json maps an Auto* class to code shipped in this repo. Loading with trust_remote_code imports and runs that code before any weights — review the publisher and the referenced module. (A dangerous sink in that module is reported separately at higher severity.)',
    remediation: 'Review the referenced module before loading, pin revision= to a reviewed commit, or use a model with native transformers support.',
    cwe: 'CWE-829',
  },
  {
    id: 'json.autotokenizer_usage',
    title: 'AutoTokenizer bound to remote code',
    severity: 'HIGH',
    category: 'remote-code',
    confidence: 0.8,
    re: /"(AutoTokenizer|AutoProcessor|AutoFeatureExtractor|AutoImageProcessor)"\s*:\s*"([^"]+)"/,
    sink: (m) => `auto_map.${m[1]}`,
    message: 'config maps a tokenizer/processor class to repo-shipped code, executed under trust_remote_code when the tokenizer loads.',
    remediation: 'Review the referenced tokenizer code before loading; prefer a model whose tokenizer ships with transformers.',
    cwe: 'CWE-829',
  },
  {
    id: 'json.trust_remote_code',
    title: 'Config declares trust_remote_code',
    severity: 'HIGH',
    category: 'remote-code',
    confidence: 0.85,
    re: /"trust_remote_code"\s*:\s*true/i,
    sink: () => '"trust_remote_code": true',
    message: 'The config pins trust_remote_code on, so any loader that honours it (transformers, sentence-transformers) will import and run the repo\'s custom code without the caller opting in.',
    remediation: 'Remove the trust_remote_code flag from the config and require callers to opt in explicitly against a reviewed, pinned revision.',
    cwe: 'CWE-94',
  },
  {
    id: 'json.custom_pipeline',
    title: 'Config binds a custom pipeline to remote code',
    severity: 'HIGH',
    category: 'remote-code',
    confidence: 0.8,
    re: /"custom_pipelines?"\s*:\s*[{"]/,
    sink: (m) => m[0].replace(/\s*:\s*[{"]$/, '').trim(),
    message: 'config.json declares a custom_pipeline, which binds the pipeline loader to code shipped in this repo — executed under trust_remote_code, before any weights, exactly like auto_map.',
    remediation: 'Remove the custom_pipeline entry, or pin revision= to a reviewed commit and read the referenced pipeline code before loading.',
    cwe: 'CWE-829',
  },
];

// ── LLM-output propagation config: LLM output → code-execution sink ─────────
// Per-language patterns for the heuristic name-propagation pass (NOT dataflow).
// `aiCall` marks a variable tainted when its RHS is an LLM/model call; `execSink`
// is the dangerous consumer. A tainted name reaching a sink is the
// prompt-injection → RCE shape — reported low-confidence, to be confirmed.
const PY_TAINT = {
  lang: 'python',
  ruleId: 'python.llm_output_to_sink',
  aiCall: /\.(a?generate|a?predict|a?invoke|a?run|complete|acomplete|chat|stream|__call__|predict_messages)\s*\(|\.(chat\.)?completions\.create\s*\(|\.messages\.create\s*\(|\bllm\s*\(/,
  execSink: /(?<![.\w])(eval|exec|compile)\s*\(|\bos\.(system|popen)\s*\(|\bsubprocess\.(run|call|check_output|check_call|Popen)\s*\(/g,
};
const JS_TAINT = {
  lang: 'js',
  ruleId: 'js.llm_output_to_sink',
  aiCall: /\.(generate|invoke|run|complete|stream|predict|call)\s*\(|\.chat\.completions\.create\s*\(|\.messages\.create\s*\(|\.create(Chat)?Completion\s*\(/,
  execSink: /(?<![.\w])eval\s*\(|\bnew\s+Function\s*\(|\b(execSync|execFileSync|spawnSync|execFile|exec|spawn)\s*\(|\bvm\.\w+\s*\(/g,
};

// ── Chain tier config: two co-occurring signals → one synthesised finding ──
const CHAINS = [
  {
    id: 'chain.decode_exec',
    title: 'Decode-and-execute packer (multi-signal)',
    severity: 'CRITICAL',
    category: 'chain',
    confidence: 0.6,
    // an encoded-blob decode AND a code-exec sink in the same file
    parts: ['python.encoded_payload', 'js.decode_and_run', 'python.dangerous_sinks', 'js.code_exec', 'python.dynamic_import'],
    needs: (ids) => (ids.has('python.encoded_payload') || ids.has('js.decode_and_run')) &&
      (ids.has('python.dangerous_sinks') || ids.has('js.code_exec') || ids.has('python.dynamic_import')),
    anchor: ['python.dangerous_sinks', 'js.code_exec', 'python.encoded_payload', 'js.decode_and_run'],
    message: 'This file BOTH decodes an encoded blob AND contains a code-execution sink — the two halves of a decode-then-run packer. Detected by co-occurrence in one file, not a proven decode→exec path, so confirm the decoded blob is what reaches the sink; when it is, this is how a hidden payload is smuggled and run.',
    remediation: 'Decode every embedded blob offline and inspect it, and remove the decode → eval/exec path entirely. Do not ship artifacts that assemble code at runtime.',
    cwe: 'CWE-506',
  },
  {
    id: 'chain.remote_code_egress',
    title: 'Remote-code model that also phones out',
    severity: 'CRITICAL',
    category: 'chain',
    confidence: 0.6,
    // remote-code loading AND network egress in the same file
    parts: ['python.trust_remote_code', 'python.torch_remote_code', 'json.automodel_usage', 'json.autotokenizer_usage', 'python.network_egress', 'js.network_egress'],
    needs: (ids) => (ids.has('python.trust_remote_code') || ids.has('python.torch_remote_code') ||
      ids.has('json.automodel_usage') || ids.has('json.autotokenizer_usage')) &&
      (ids.has('python.network_egress') || ids.has('js.network_egress')),
    anchor: ['python.network_egress', 'js.network_egress', 'python.trust_remote_code', 'python.torch_remote_code'],
    message: 'This file loads code shipped in a model repo (trust_remote_code / auto_map / torch.hub) AND opens a network connection. Detected by co-occurrence in one file, not a proven load→egress path. Remote-code modeling that also phones out is the classic staged-download / exfiltration shape — confirm whether the network call is reachable from the model-code load.',
    remediation: 'Do not load remote model code; use a native-transformers model or a reviewed, pinned revision. Model code should never make outbound requests — treat this artifact as hostile.',
    cwe: 'CWE-494',
  },
];

function contextChunk(lines, idx) {
  const start = Math.max(0, idx - CONTEXT_RADIUS);
  const end = Math.min(lines.length - 1, idx + CONTEXT_RADIUS);
  const snippet = lines.slice(start, end + 1).join('\n').slice(0, MAX_SNIPPET);
  return { snippet, snippetStartLine: start + 1 };
}

function isCommentLine(trimmed) {
  return trimmed.startsWith('#') || trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*');
}

/**
 * Net bracket-depth change contributed by one physical line, plus whether it ends
 * in a Python line-continuation backslash. Quote- and comment-aware so brackets
 * inside string literals or after `#` / `//` don't skew the count.
 */
function lineDepthDelta(line) {
  let delta = 0;
  let quote = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (c === '\\') { i++; continue; }
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') { quote = c; continue; }
    if (c === '#') break;
    if (c === '/' && line[i + 1] === '/') break;
    if (c === '(' || c === '[' || c === '{') delta++;
    else if (c === ')' || c === ']' || c === '}') delta--;
  }
  return { delta, backslash: !quote && /\\\s*$/.test(line) };
}

/**
 * Group physical lines into logical statements. A line continues the current
 * statement while brackets stay open (call arguments / dicts / arrays that span
 * lines) or it ends in a backslash. This is what lets one line-oriented regex
 * match a call whose sink and its dangerous argument sit on DIFFERENT lines —
 * e.g. `torch.load(\n    ckpt,\n    weights_only=False,\n)` — which a strict
 * per-physical-line scan silently misses. Bounded by MAX_JOIN_LINES.
 */
function logicalLines(lines) {
  const out = [];
  let i = 0;
  while (i < lines.length) {
    const startLine = i + 1;
    const buf = [];
    let depth = 0;
    while (i < lines.length) {
      const line = lines[i];
      buf.push(line);
      const { delta, backslash } = lineDepthDelta(line);
      depth += delta;
      i++;
      if ((depth <= 0 && !backslash) || buf.length >= MAX_JOIN_LINES) break;
    }
    out.push({ text: buf.join('\n'), startLine });
  }
  return out;
}

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Whether byte `offset` in `text` falls inside a string literal — tracks single/
 * double/backtick + triple quotes, honouring escapes. Drops `codeOnly` rule
 * matches that land in a docstring / log message / usage example (the Falcon
 * `trust_remote_code=True`-in-a-warning FP). Approximate and only ever more
 * conservative (may skip a real hit, never invents one).
 */
function isInsideString(text, offset) {
  let quote = null;
  let triple = false;
  for (let i = 0; i < offset && i < text.length; i++) {
    const c = text[i];
    if (quote) {
      if (c === '\\') { i++; continue; }
      if (triple) {
        if (c === quote && text[i + 1] === quote && text[i + 2] === quote) { i += 2; quote = null; triple = false; }
      } else if (c === quote) {
        quote = null;
      }
      continue;
    }
    if (c === '#') {
      const nl = text.indexOf('\n', i);
      if (nl === -1) return false;
      i = nl;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') {
      quote = c;
      triple = text[i + 1] === c && text[i + 2] === c;
      if (triple) i += 2;
    }
  }
  return quote !== null;
}

/** Map a match offset inside a logical unit back to a 0-based physical line. */
function physicalIdx(unit, offset) {
  const newlines = unit.text.slice(0, offset).match(/\n/g);
  return unit.startLine - 1 + (newlines ? newlines.length : 0);
}

/**
 * Parse a leading assignment out of a logical unit: `x = …`, `const x = …`,
 * `x: T = …`, or tuple unpacking `a, b = …`. Rejects `==`/`=>`/`>=` etc. Returns
 * the assigned variable names and the RHS text, or null.
 */
function parseAssign(text) {
  const m = /^\s*(?:export\s+)?(?:const|let|var|await\s+)?\s*([A-Za-z_$][\w$]*(?:\s*,\s*[A-Za-z_$][\w$]*)*)\s*(?::[^=\n]+?)?=(?![=>])\s*([\s\S]+)$/.exec(text);
  if (!m) return null;
  const vars = m[1].split(',').map((s) => s.trim()).filter(Boolean);
  return { vars, rhs: m[2] };
}

/**
 * Heuristic intra-file LLM-output propagation (NOT true taint analysis). Marks
 * variables assigned from an LLM call as tainted, propagates by name-substring
 * across simple assignments (bounded fixed point), then emits a finding wherever
 * a tainted name appears in a code-exec sink's arguments — the prompt-injection →
 * RCE shape a single-sink regex can't see. No scope, kill, sanitizer or
 * interprocedural tracking, so it can over- and under-report; findings are HIGH
 * at low confidence with hedged wording, i.e. leads to confirm, not proof.
 */
function taintFindings(lines, units, file, cfg) {
  const tainted = new Set();
  // Seed + propagate. Two passes cover simple multi-hop chains (resp → text → exec).
  for (let pass = 0; pass < 2; pass++) {
    for (const unit of units) {
      const a = parseAssign(unit.text);
      if (!a) continue;
      let taint = cfg.aiCall.test(a.rhs);
      if (!taint) {
        for (const t of tainted) {
          if (new RegExp(`\\b${escapeRe(t)}\\b`).test(a.rhs)) { taint = true; break; }
        }
      }
      if (taint) for (const v of a.vars) tainted.add(v);
    }
    if (!tainted.size) break;
  }
  if (!tainted.size) return [];

  const out = [];
  const seen = new Set();
  for (const unit of units) {
    cfg.execSink.lastIndex = 0;
    let m;
    while ((m = cfg.execSink.exec(unit.text))) {
      // Argument region: from the sink's '(' to the end of the logical unit.
      const paren = unit.text.indexOf('(', m.index);
      const argRegion = paren >= 0 ? unit.text.slice(paren) : '';
      let via = null;
      for (const t of tainted) {
        if (new RegExp(`\\b${escapeRe(t)}\\b`).test(argRegion)) { via = t; break; }
      }
      if (via) {
        const idx = physicalIdx(unit, m.index);
        const trimmed = (lines[idx] ?? '').trim();
        if (trimmed && !isCommentLine(trimmed) && !seen.has(idx)) {
          seen.add(idx);
          const sink = m[0].replace(/\s*\($/, '').trim();
          out.push({
            ruleId: cfg.ruleId,
            title: 'LLM output may reach a code-execution sink (heuristic)',
            // HIGH, not CRITICAL: name-propagation heuristic, not proven dataflow.
            severity: 'HIGH',
            category: 'taint-heuristic',
            confidence: 0.5,
            file,
            line: idx + 1,
            sink: sink.slice(0, 120),
            source: 'LLM output',
            taint: `${via} (LLM output) → ${sink} (heuristic name match — confirm)`,
            ...contextChunk(lines, idx),
            message: `A variable that appears to derive from an LLM call ("${via}") is used in ${sink}. If that value really is model-controlled, a prompt-injected instruction becomes code execution in the host — a critical agent vulnerability. Flagged by a name-propagation heuristic (no dataflow proof), so confirm the value is actually the model output and not reassigned/sanitized before this line.`,
            remediation: 'If confirmed, never pass model output to eval/exec/subprocess. Constrain the model to structured output (a fixed schema / tool-call allowlist), validate it, and dispatch on named handlers — never execute it.',
            cwe: 'CWE-94',
          });
        }
      }
      if (!cfg.execSink.global) break;
    }
  }
  return out;
}

/**
 * Synthesise chain findings from co-occurring rule hits in one file. Conjunctions
 * only (both halves independently suspicious), so no added false positives.
 */
function chainFindings(lines, findings, file) {
  const ids = new Set(findings.map((f) => f.ruleId));
  const out = [];
  for (const chain of CHAINS) {
    if (!chain.needs(ids)) continue;
    // Anchor the synthesised finding on a real contributing line for the snippet.
    const anchor = findings.find((f) => chain.anchor.includes(f.ruleId));
    const line = anchor ? anchor.line : 1;
    const idx = Math.max(0, line - 1);
    out.push({
      ruleId: chain.id,
      title: chain.title,
      severity: chain.severity,
      category: chain.category,
      confidence: chain.confidence,
      file,
      line,
      sink: 'multi-signal',
      chain: [...new Set(findings.filter((f) => chain.parts.includes(f.ruleId)).map((f) => f.ruleId))],
      ...contextChunk(lines, idx),
      message: chain.message,
      remediation: chain.remediation,
      cwe: chain.cwe,
    });
  }
  return out;
}

/**
 * Run each rule over the file, grouping physical lines into logical statements
 * first so multi-line calls are matched, then layer the taint and chain tiers on
 * top. The reported `line` is the exact physical line the sink lands on, so the
 * numbered snippet still highlights the right row. Hits on pure comment lines are
 * skipped.
 */
function scanLines(text, file, rules, taintCfg) {
  const lines = text.split(/\r?\n/);
  const units = logicalLines(lines);
  const out = [];
  const seen = new Set(); // dedupe by ruleId@line
  for (const unit of units) {
    for (const rule of rules) {
      rule.re.lastIndex = 0;
      const m = rule.re.exec(unit.text);
      if (!m) continue;
      // Drop code-construct rules whose match lands inside a string literal
      // (docstring / log message / usage example) — the Falcon-class FP.
      if (rule.codeOnly && isInsideString(unit.text, m.index)) continue;
      const idx = physicalIdx(unit, m.index);
      const trimmed = (lines[idx] ?? '').trim();
      if (!trimmed || isCommentLine(trimmed)) continue;
      const key = `${rule.id}@${idx}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({
        ruleId: rule.id,
        title: rule.title,
        severity: rule.severity,
        category: rule.category,
        confidence: rule.confidence,
        file,
        line: idx + 1,
        sink: (rule.sink ? rule.sink(m) : m[0]).slice(0, 120),
        source: rule.source || undefined,
        ...contextChunk(lines, idx),
        message: rule.message,
        remediation: rule.remediation,
        cwe: rule.cwe,
      });
    }
  }
  if (taintCfg) out.push(...taintFindings(lines, units, file, taintCfg));
  out.push(...chainFindings(lines, out, file));
  return out;
}

export function scanPythonSource(text, file) { return text ? scanLines(text, file, PY_RULES, PY_TAINT) : []; }
export function scanJsSource(text, file) { return text ? scanLines(text, file, JS_RULES, JS_TAINT) : []; }
export function scanModelConfig(text, file) { return text ? scanLines(text, file, CONFIG_RULES, null) : []; }

/**
 * Scan a Jupyter notebook (`.ipynb`, which is JSON). Notebooks ship executable
 * code cells and are a first-class model-hub / agent delivery vector, but line
 * numbers only make sense per cell, so each `code` cell is scanned on its own and
 * tagged `<file>#cell<N>` with 1-based lines within that cell. The kernel language
 * routes Python vs JS rules (default Python). Malformed JSON yields nothing rather
 * than throwing, so one bad file never breaks a scan.
 */
export function scanNotebook(text, file) {
  if (!text) return [];
  let nb;
  try { nb = JSON.parse(text); } catch { return []; }
  const cells = Array.isArray(nb?.cells) ? nb.cells : [];
  const lang = String(nb?.metadata?.kernelspec?.language || nb?.metadata?.language_info?.name || 'python').toLowerCase();
  const isJs = /javascript|typescript|deno|node|^js$|^ts$/.test(lang);
  const rules = isJs ? JS_RULES : PY_RULES;
  const taintCfg = isJs ? JS_TAINT : PY_TAINT;
  const out = [];
  let codeCell = 0;
  for (const cell of cells) {
    if (cell?.cell_type !== 'code') continue;
    codeCell++;
    const src = Array.isArray(cell.source) ? cell.source.join('') : String(cell.source ?? '');
    if (!src.trim()) continue;
    out.push(...scanLines(src, `${file}#cell${codeCell}`, rules, taintCfg));
  }
  return out;
}

const PY_EXT = /\.py$/i;
const JS_EXT = /\.(m|c)?[jt]sx?$/i;
const NB_EXT = /\.ipynb$/i;
const MODEL_CONFIG_RE = /(^|\/)(config|tokenizer_config|generation_config|preprocessor_config)\.json$/i;

/** True when `path` is a source file one of the language rule sets can scan. */
export function isScannableSource(path) {
  return PY_EXT.test(path) || JS_EXT.test(path) || NB_EXT.test(path);
}

/** True when `path` is a HF-style model config the auto_map rules understand. */
export function isModelConfig(path) {
  return MODEL_CONFIG_RE.test(String(path ?? '').split(/[\\/]+/).join('/'));
}

/**
 * Route one file to the right rule set by name/extension and return its hits.
 * Unknown files yield nothing.
 */
export function scanSourceFile(text, file) {
  if (!text) return [];
  if (NB_EXT.test(file)) return scanNotebook(text, file);
  if (PY_EXT.test(file)) return scanPythonSource(text, file);
  if (JS_EXT.test(file)) return scanJsSource(text, file);
  if (isModelConfig(file)) return scanModelConfig(text, file);
  return [];
}
