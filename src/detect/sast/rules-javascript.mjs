import { isNotAModuleLoad, isStaticPathExpr } from './path-expressions.mjs';
import { callArgText } from './source-lines.mjs';

export const JS_RULES = [
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

    severity: 'LOW',
    category: 'agentic',
    confidence: 0.55,

    re: /@modelcontextprotocol\/sdk\/client|\b(StdioClientTransport|SSEClientTransport|StreamableHTTPClientTransport|WebSocketClientTransport)\b/,
    sink: (m) => m[0].trim(),
    source: 'MCP server tool output',
    message: 'Acts as an MCP client/host: connects to MCP servers and passes their tool descriptions and results back to a model. Every server it reaches is an untrusted-input ingress - a poisoned tool description or result can hijack the agent (prompt injection / tool poisoning).',
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
    message: 'Decodes an encoded string and immediately executes it - the packer pattern used to hide malicious code inside an otherwise innocuous-looking tool.',
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

    suppress: (m, unitText, ctx) => {
      const arg = callArgText(unitText, m.index);
      return isNotAModuleLoad(m, unitText, arg) || isStaticPathExpr(arg, ctx.pathNs, ctx.constPaths);
    },
    sink: (m) => m[0].trim(),
    message: 'Loads a module chosen at runtime rather than a string literal, often to conceal which dangerous module is imported.',
    remediation: 'Import modules by string literal so the dependency is statically reviewable; remove runtime-computed requires.',
    cwe: 'CWE-829',
  },
  {
    id: 'js.network_egress',
    title: 'Network egress',

    severity: 'MEDIUM',
    category: 'egress',
    confidence: 0.5,
    re: /\baxios\s*\.\s*(get|post|put|request)\s*\(|\bhttps?\.request\s*\(|\bnet\.(connect|createConnection)\s*\(|\bnew\s+WebSocket\s*\(|require\(\s*['"](node-fetch|got|undici|axios)['"]/,
    sink: (m) => m[0].replace(/\s*\($/, '').trim(),
    source: 'network',
    message: 'Opens an outbound network connection. Normal in application code; chained with a reads-secrets or remote-code-load finding this is the exfiltration / second-stage-download shape.',
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

export const JS_TAINT = {
  lang: 'js',
  ruleId: 'js.llm_output_to_sink',
  aiCall: /\.(generate|invoke|run|complete|stream|predict|call)\s*\(|\.chat\.completions\.create\s*\(|\.messages\.create\s*\(|\.create(Chat)?Completion\s*\(/,
  execSink: /(?<![.\w])eval\s*\(|\bnew\s+Function\s*\(|\b(execSync|execFileSync|spawnSync|execFile|exec|spawn)\s*\(|\bvm\.\w+\s*\(/g,
};
