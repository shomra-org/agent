// GENERATED MIRROR of Dragox.Backend model-formats/scanners/onnx-scan.ts (types stripped, imports swapped).
// Do not hand-edit - change the backend file and run scripts/mirror-model-config.mjs,
// so `shomra model-scan <path>` and the platform read a weight file identically.
                                                                            
                                                        
import { inspectText } from '../signals/inspect-shim.mjs';
import { pbWalk, pbGet, pbString,             } from './protobuf-lite.mjs';
const binaryFinding = () => (f) => f;

const MAX_SCAN_BYTES = 8 * 1024 * 1024;

const ONNX = { IR_VERSION: 1, PRODUCER_NAME: 2, DOC_STRING: 6, GRAPH: 7, OPSET_IMPORT: 8, METADATA_PROPS: 14 }         ;
const GRAPH = { NODE: 1, INITIALIZER: 5, DOC_STRING: 10 }         ;
const NODE = { OP_TYPE: 4, DOMAIN: 7 }         ;
const TENSOR = { NAME: 8, EXTERNAL_DATA: 13 }         ;
const ENTRY = { KEY: 1, VALUE: 2 }         ;
const OPSET = { DOMAIN: 1 }         ;

const MAX_NODES = 20_000;
const MAX_INITIALIZERS = 5_000;
const MAX_GRAPHS = 4;

const STANDARD_DOMAINS = new Set([
  '',
  'ai.onnx',
  'ai.onnx.ml',
  'ai.onnx.training',
  'ai.onnx.preview.training',
  'com.microsoft',
  'com.microsoft.nchwc',
  'com.microsoft.experimental',
  'com.ms.internal.nhwc',
  'org.pytorch.aten',
]);

const PYOP_DOMAIN = /^ai\.onnx\.contrib$|^ai\.onnx\.pyop$/i;
const PYOP_MARKER = /ai\.onnx\.contrib|\bPyOp\b|onnxruntime_extensions/;


const EXTERNAL_DATA_ESCAPE = {
  ruleId: 'onnx.external_data_escape',
  title: 'ONNX external tensor points outside the model directory',
  severity: 'HIGH'            ,
  cwe: 'CWE-22',
};

const PYTHON_CALLBACK_OP = {
  ruleId: 'onnx.python_op',
  title: 'ONNX graph invokes a Python callback op',
  severity: 'HIGH'            ,
  cwe: 'CWE-94',
};

const MAX_ESCAPES = 8;

function escapesModelDirectory(raw        )          {
  if (/\.\.[/\\]/.test(raw)) return true;
  for (const candidate of [raw, raw.slice(1), raw.slice(2)]) {
    if (/^[A-Za-z]:[/\\]/.test(candidate)) return true;
    if (/^\\\\[A-Za-z0-9]/.test(candidate)) return true;
    if (/^[a-z][a-z0-9+.-]{1,10}:\/\//i.test(candidate)) return true;
    if (/^[/\\](?:[\w.-]+[/\\])+[\w.-]/.test(candidate)) return true;
  }
  return false;
}

function displayPath(raw        )         {
  return raw.replace(/^[^\w./\\~-]+/, '');
}

const finding = binaryFinding('onnx model load', 'deserialization');

                            
                          

                         

                        

                    

                                         

                                                            

                     
 

function entryOf(buf        )                                 {
  const w = pbWalk(buf);
  return { key: pbString(w, ENTRY.KEY) ?? '', value: pbString(w, ENTRY.VALUE) ?? '' };
}

export function readOnnx(buf        )                   {
  const walk         = pbWalk(buf);
  if (!walk.clean && !walk.truncated) return null;
  const has = (n        ) => walk.fields.some((f) => f.field === n);
  if (!has(ONNX.IR_VERSION) || !(has(ONNX.GRAPH) || has(ONNX.PRODUCER_NAME) || has(ONNX.OPSET_IMPORT))) return null;

  const out            = {
    producer: pbString(walk, ONNX.PRODUCER_NAME),
    opsetDomains: [],
    nodeDomains: [],
    opTypes: [],
    text: [],
    externalLocations: [],
    truncated: walk.truncated,
  };

  for (const b of pbGet(walk, ONNX.OPSET_IMPORT)) {
    out.opsetDomains.push(pbString(pbWalk(b), OPSET.DOMAIN) ?? '');
  }
  for (const b of pbGet(walk, ONNX.METADATA_PROPS)) out.text.push(entryOf(b));
  const modelDoc = pbString(walk, ONNX.DOC_STRING);
  if (modelDoc) out.text.push({ key: 'doc_string', value: modelDoc });

  for (const g of pbGet(walk, ONNX.GRAPH).slice(0, MAX_GRAPHS)) {
    const gw = pbWalk(g);
    if (gw.truncated) out.truncated = true;
    const gdoc = pbString(gw, GRAPH.DOC_STRING);
    if (gdoc) out.text.push({ key: 'graph.doc_string', value: gdoc });

    for (const n of pbGet(gw, GRAPH.NODE).slice(0, MAX_NODES)) {
      const nw = pbWalk(n);
      const dom = pbString(nw, NODE.DOMAIN);
      if (dom) out.nodeDomains.push(dom);
      const op = pbString(nw, NODE.OP_TYPE);
      if (op) out.opTypes.push(op);
    }
    for (const t of pbGet(gw, GRAPH.INITIALIZER).slice(0, MAX_INITIALIZERS)) {
      const tw = pbWalk(t);
      const name = pbString(tw, TENSOR.NAME) ?? '(unnamed)';
      for (const e of pbGet(tw, TENSOR.EXTERNAL_DATA)) {
        const { key, value } = entryOf(e);
        if (key === 'location' && value) out.externalLocations.push({ tensor: name, location: value });
      }
    }
  }

  out.opsetDomains = [...new Set(out.opsetDomains)];
  out.nodeDomains = [...new Set(out.nodeDomains)];
  out.opTypes = [...new Set(out.opTypes)];
  return out;
}

export function looksLikeOnnx(buf        )          {
  return buf.length >= 8 && readOnnx(buf) !== null;
}

                                 
                          

                          

                     

                     

                      
 

export function scanOnnxModel(buf        , file        )                 {
  const model = readOnnx(buf);
  return model ? scanStructural(model, buf, file) : scanByMarkers(buf, file);
}

function scanStructural(m           , buf        , file        )                 {
  const findings                = [];

  const seen = new Set        ();
  for (const { tensor, location } of m.externalLocations) {
    if (!escapesModelDirectory(location) || seen.has(location)) continue;
    seen.add(location);
    findings.push(
      finding({
        ...EXTERNAL_DATA_ESCAPE,
        file,
        sink: `external_data.location=${location.slice(0, 120)}`,
        snippet: `tensor "${tensor}" → location: ${location.slice(0, 200)}`,
        message:
          `This ONNX graph stores tensor \`${tensor}\` externally and names its location as ` +
          `\`${location.slice(0, 120)}\` - a path that leaves the model directory. \`onnx.load\` follows that ` +
          "path and reads it with the loading process's privileges, and `onnx.save_model` will WRITE to it " +
          '(CVE-2024-5187 / CVE-2022-25882). A legitimate external-data location is a plain sibling file name.',
        remediation:
          'Do not load this model. If you must, load with `load_external_data=False` and inspect the graph, or ' +
          'upgrade onnx to a version that constrains external paths to the model directory and confirm it refuses this file.',
        confidence: 0.95,
      }),
    );
    if (seen.size >= MAX_ESCAPES) break;
  }

  const pyDomains = [...m.opsetDomains, ...m.nodeDomains].filter((d) => PYOP_DOMAIN.test(d));
  const pyByOp = m.opTypes.some((o) => /^PyOp$/i.test(o));
  if (pyDomains.length || pyByOp) {
    findings.push(
      finding({
        ...PYTHON_CALLBACK_OP,
        file,
        sink: pyDomains[0] ?? 'PyOp',
        snippet: [...pyDomains, ...m.opTypes.filter((o) => /^PyOp$/i.test(o))].join('\n').slice(0, 400),
        message:
          'This graph declares the onnxruntime-extensions Python-op surface (`ai.onnx.contrib` / `PyOp`). Such a ' +
          'node names a Python function that the runtime imports and calls during inference, so running this model ' +
          'executes Python in the serving process - the property ONNX is otherwise chosen for not having.',
        remediation:
          'Do not serve this model in a shared process. Obtain a graph built from standard ops, or run it isolated ' +
          'with onnxruntime-extensions absent so the op cannot resolve.',
        confidence: 0.95,
      }),
    );
  }

  const customDomains = [...new Set([...m.opsetDomains, ...m.nodeDomains])]
    .filter((d) => !STANDARD_DOMAINS.has(d) && !PYOP_DOMAIN.test(d))
    .sort()
    .slice(0, 12);
  if (customDomains.length && !pyDomains.length && !pyByOp) {
    findings.push(
      finding({
        ruleId: 'onnx.custom_op_domain',
        title: 'ONNX graph requires third-party custom operators',
        severity: 'MEDIUM',
        file,
        sink: customDomains[0],
        snippet: customDomains.join('\n'),
        message:
          `This graph declares operators in non-standard domains (${customDomains.slice(0, 4).join(', ')}). The ` +
          'runtime cannot execute them until a shared library registering those ops is loaded into the serving ' +
          'process - so using this model means loading third-party native code alongside it, which is a supply-chain ' +
          'decision rather than a model decision.',
        remediation:
          'Identify which package provides these operators and review it as a dependency, or obtain a model built ' +
          'from the standard opset. Never auto-load an op library named by an untrusted model.',
        cwe: 'CWE-829',
        confidence: 0.9,
      }),
    );
  }

  for (const { key, value } of m.text) {
    if (!value || value.length < 12) continue;
    const signals = inspectText(value, { categories: ['injection'] }).matches;
    if (!signals.length) continue;
    findings.push(
      finding({
        ruleId: 'onnx.metadata_injection',
        title: `Injected instructions in ONNX model metadata (${key || 'metadata_props'})`,
        severity: 'MEDIUM',
        file,
        sink: `metadata_props.${key}`,
        snippet: value.slice(0, 400),
        message:
          `The ONNX metadata entry \`${key}\` contains injected instructions. Serving stacks surface model ` +
          'metadata and catalog tooling ingests it, so this text reaches an agent context without anyone choosing ' +
          'to show it. Signals: ' +
          signals
            .map((x) => x.label)
            .slice(0, 4)
            .join('; '),
        remediation:
          'Strip the metadata_props/doc_string entries before publishing or serving, and do not feed model ' +
          'metadata into an agent context unreviewed.',
        cwe: 'CWE-94',
        category: 'agentic',
        confidence: 0.9,
      }),
    );
    break;
  }

  return { findings, customDomains, truncated: m.truncated, blindSpot: false, structural: true };
}

function scanByMarkers(buf        , file        )                 {
  const truncated = buf.length > MAX_SCAN_BYTES;
  const text = buf.toString('latin1', 0, Math.min(buf.length, MAX_SCAN_BYTES));
  const findings                = [];

  const LOCATION_RE = /location[\x00-\x20"']{0,8}([^\x00-\x1f"']{1,240})/g;
  const seen = new Set        ();
  LOCATION_RE.lastIndex = 0;
  let m                        ;
  while ((m = LOCATION_RE.exec(text))) {
    const raw = m[1].trim();
    if (!raw || !escapesModelDirectory(raw)) continue;
    const loc = displayPath(raw);
    if (!loc || seen.has(loc)) continue;
    seen.add(loc);
    findings.push(
      finding({
        ...EXTERNAL_DATA_ESCAPE,
        file,
        sink: `external_data.location=${loc.slice(0, 120)}`,
        snippet: `location: ${loc.slice(0, 200)}`,
        message:
          `This ONNX file names an external tensor location of \`${loc.slice(0, 120)}\` - a path that leaves the ` +
          "model directory. `onnx.load` follows it and reads it with the loading process's privileges, and " +
          '`onnx.save_model` will WRITE to it (CVE-2024-5187 / CVE-2022-25882).',
        remediation:
          'Do not load this model. If you must, load with `load_external_data=False` and inspect the graph first.',
        confidence: 0.6,
      }),
    );
    if (seen.size >= MAX_ESCAPES) break;
  }

  if (PYOP_MARKER.test(text)) {
    findings.push(
      finding({
        ...PYTHON_CALLBACK_OP,
        file,
        sink: 'ai.onnx.contrib / PyOp',
        snippet: (PYOP_MARKER.exec(text)?.[0] ?? 'PyOp').slice(0, 200),
        message:
          'This file references the onnxruntime-extensions Python-op surface (`ai.onnx.contrib` / `PyOp`), which ' +
          'names a Python function the runtime imports and calls during inference.',
        remediation: 'Do not serve this model in a shared process; obtain a graph built from standard ops.',
        confidence: 0.6,
      }),
    );
  }

  return {
    findings,
    customDomains: [],
    truncated,
    blindSpot: findings.length === 0,
    structural: false,
  };
}

export const ONNX_SCAN_EXTS = ['.onnx', '.ort'];

export function isOnnxScannable(path        )          {
  const i = path.lastIndexOf('.');
  return i !== -1 && ONNX_SCAN_EXTS.includes(path.slice(i).toLowerCase());
}
