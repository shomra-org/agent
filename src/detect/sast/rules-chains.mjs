export const CHAINS = [
  {
    id: 'chain.decode_exec',
    title: 'Decode-and-execute packer (multi-signal)',
    severity: 'CRITICAL',
    category: 'chain',
    confidence: 0.6,

    parts: ['python.encoded_payload', 'js.decode_and_run', 'python.dangerous_sinks', 'js.code_exec', 'python.dynamic_import'],
    needs: (ids) => (ids.has('python.encoded_payload') || ids.has('js.decode_and_run')) &&
      (ids.has('python.dangerous_sinks') || ids.has('js.code_exec') || ids.has('python.dynamic_import')),
    anchor: ['python.dangerous_sinks', 'js.code_exec', 'python.encoded_payload', 'js.decode_and_run'],
    message: 'This file BOTH decodes an encoded blob AND contains a code-execution sink - the two halves of a decode-then-run packer. Detected by co-occurrence in one file, not a proven decode→exec path, so confirm the decoded blob is what reaches the sink; when it is, this is how a hidden payload is smuggled and run.',
    remediation: 'Decode every embedded blob offline and inspect it, and remove the decode → eval/exec path entirely. Do not ship artifacts that assemble code at runtime.',
    cwe: 'CWE-506',
  },
  {
    id: 'chain.remote_code_egress',
    title: 'Remote-code model that also phones out',
    severity: 'CRITICAL',
    category: 'chain',
    confidence: 0.6,

    parts: ['python.trust_remote_code', 'python.torch_remote_code', 'json.automodel_usage', 'json.autotokenizer_usage', 'python.network_egress', 'js.network_egress'],
    needs: (ids) => (ids.has('python.trust_remote_code') || ids.has('python.torch_remote_code') ||
      ids.has('json.automodel_usage') || ids.has('json.autotokenizer_usage')) &&
      (ids.has('python.network_egress') || ids.has('js.network_egress')),
    anchor: ['python.network_egress', 'js.network_egress', 'python.trust_remote_code', 'python.torch_remote_code'],
    message: 'This file loads code shipped in a model repo (trust_remote_code / auto_map / torch.hub) AND opens a network connection. Detected by co-occurrence in one file, not a proven load→egress path. Remote-code modeling that also phones out is the classic staged-download / exfiltration shape - confirm whether the network call is reachable from the model-code load.',
    remediation: 'Do not load remote model code; use a native-transformers model or a reviewed, pinned revision. Model code should never make outbound requests - treat this artifact as hostile.',
    cwe: 'CWE-494',
  },
];
