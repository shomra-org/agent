// GENERATED MIRROR of Dragox.Backend model-formats/scanners/keras-scan.ts (types stripped, imports swapped).
// Do not hand-edit - change the backend file and run scripts/mirror-model-config.mjs,
// so `shomra model-scan <path>` and the platform read a weight file identically.
import { walkZipEntries } from './zip-walk.mjs';
import { looksLikeProtobuf } from './protobuf-lite.mjs';
                                                                            
                                                        

const DANGEROUS_MODULES = [
  'os', 'nt', 'posix', 'subprocess', 'sys', 'builtins', '__builtin__', 'shutil',
  'socket', 'importlib', 'ctypes', '_ctypes', 'runpy', 'pickle', '_pickle',
  'marshal', 'dill', 'cloudpickle', 'pty', 'code', 'codeop', 'requests',
  'urllib', 'urllib2', 'httplib', 'multiprocessing', 'pip', 'webbrowser',
  'commands', 'popen2',
];

const MODULE_REF_RE = /["']module["']\s*:\s*["']([^"']+)["']/g;

const LAMBDA_RE = /["']class_name["']\s*:\s*["']Lambda["']/;

const FUNCTION_PAYLOAD_RE = /["']class_name["']\s*:\s*["']__lambda__["']|["']python_function["']|["']function["']\s*:\s*\[/;

                                  
                          
                                      

                     

                         
 

const HDF5_MAGIC = Buffer.from([0x89, 0x48, 0x44, 0x46, 0x0d, 0x0a, 0x1a, 0x0a]);
const ZIP_MAGIC = Buffer.from([0x50, 0x4b, 0x03, 0x04]);

const MAX_TEXT = 4 * 1024 * 1024;

function startsWith(buf        , magic        )          {
  return buf.length >= magic.length && buf.subarray(0, magic.length).equals(magic);
}


function kerasZipConfig(buf        )                                               {
  const parts           = [];
  let total = 0;
  let unreadable = false;

  const MAX_CONFIG_TEXT = 8 * 1024 * 1024;
  for (const entry of walkZipEntries(buf, {
    match: /(^|\/)(config|metadata)\.json$/i,
    maxCompressed: 4 * 1024 * 1024,
    maxInflated: 8 * 1024 * 1024,
    maxTotal: MAX_CONFIG_TEXT,
  })) {
    if (entry.unreadable) {
      unreadable = true;
      continue;
    }
    parts.push(entry.bytes.toString('utf8'));
    total += entry.bytes.length;
    if (total >= MAX_CONFIG_TEXT) break;
  }
  return { text: parts.length ? parts.join('\n').slice(0, MAX_CONFIG_TEXT) : null, unreadable };
}

function analyzeConfigText(text        , file        , format        )                {
  const out                = [];

  const seen = new Set        ();
  MODULE_REF_RE.lastIndex = 0;
  let m                        ;
  while ((m = MODULE_REF_RE.exec(text))) {
    const mod = m[1];
    const root = mod.split('.')[0];
    if (DANGEROUS_MODULES.includes(root) && !seen.has(mod)) {
      seen.add(mod);
      out.push(finding({
        ruleId: 'keras.arbitrary_import',
        title: 'Keras config imports a dangerous module',
        severity: 'CRITICAL',
        file,
        sink: `module:${mod}`,
        message:
          `The ${format} model config names \`${mod}\` in a "module" field. Keras deserialize_keras_object imports that module and resolves the config's class_name/function on it while loading the model - importing os/subprocess/builtins here is arbitrary code execution on load (CVE-2025-1550 class).`,
        remediation:
          'Do not load this model. A legitimate Keras config only references keras/tensorflow modules; a reference to os/subprocess/builtins is malicious. Obtain the model from a trusted source in safetensors form.',
        cwe: 'CWE-502',
      }));
    }
  }

  if (LAMBDA_RE.test(text)) {
    const payload = FUNCTION_PAYLOAD_RE.test(text);
    out.push(finding({
      ruleId: 'keras.lambda_layer',
      title: payload ? 'Keras Lambda layer with a serialized function' : 'Keras Lambda layer',
      severity: payload ? 'CRITICAL' : 'HIGH',
      file,
      sink: 'Lambda',
      message:
        `The ${format} model contains a Lambda layer${payload ? ' with a serialized (marshalled) function' : ''}. Loading with safe_mode=False - or on Keras versions where that was the default - marshal.loads() and runs that function in the host process (CVE-2024-3660 class). The model file alone is enough; no loader code is needed.`,
      remediation:
        'Do not load this model with safe_mode=False. Prefer a model with no Lambda layers, or reimplement the Lambda as a reviewed Keras layer subclass and reserialize. Treat an untrusted Lambda-bearing model as hostile.',
      cwe: 'CWE-502',
    }));
  }
  return out;
}

export function scanKerasModel(buf        , file        )                  {
  let format                            = null;
  let configText                = null;
  let unreadableMember = false;

  if (startsWith(buf, ZIP_MAGIC) || file.toLowerCase().endsWith('.keras')) {
    format = 'keras-zip';
    const zip = kerasZipConfig(buf);
    configText = zip.text;
    unreadableMember = zip.unreadable;

    if (!configText) configText = buf.toString('latin1', 0, MAX_TEXT);
  } else if (startsWith(buf, HDF5_MAGIC) || /\.(h5|hdf5)$/i.test(file)) {
    format = 'hdf5';

    configText = buf.toString('latin1', 0, MAX_TEXT);
  }

  if (!format || !configText) {
    return { findings: [], format, blindSpot: unreadableMember || format !== null, notApplicable: format === null };
  }

  const findings = analyzeConfigText(configText, file, format === 'hdf5' ? 'HDF5/Keras' : 'Keras');

  const sawConfig = /["']class_name["']/.test(configText);

  const sawKerasStamp = /keras_version|model_config|backend|["']module["']/.test(configText);
  const blindSpot = unreadableMember || (findings.length === 0 && !sawConfig && sawKerasStamp);
  const notApplicable = findings.length === 0 && !sawConfig && !sawKerasStamp;
  return { findings, format, blindSpot, notApplicable };
}

function finding(p   
                 
                
                     
               
               
                  
                      
              
 )              {
  return {
    ruleId: p.ruleId,
    title: p.title,
    severity: p.severity,
    category: 'deserialization',
    confidence: 0.9,
    file: p.file,
    line: 1,
    sink: p.sink,
    source: 'model file load',
    snippet: `# ${p.sink} in ${p.file}`,
    snippetStartLine: 1,
    message: p.message,
    remediation: p.remediation,
    cwe: p.cwe,
  };
}

export const KERAS_SCAN_EXTS = ['.h5', '.hdf5', '.keras'];

export function isKerasScannable(path        )          {
  const i = path.lastIndexOf('.');
  return i !== -1 && KERAS_SCAN_EXTS.includes(path.slice(i).toLowerCase());
}

const PYFUNC_RE = /\b(EagerPyFunc|PyFuncStateless|PyFunc)\b/;
const WRITEFILE_RE = /\bWriteFile\b/;

                                       
                          

                     

                         
 

export function scanSavedModel(buf        , file        )                       {
  const text = buf.toString('latin1', 0, MAX_TEXT);
  const findings = analyzeConfigText(text, file, 'TF SavedModel');

  if (PYFUNC_RE.test(text)) {
    findings.push(finding({
      ruleId: 'savedmodel.pyfunc',
      title: 'TF SavedModel contains a Python-callback op',
      severity: 'MEDIUM',
      file,
      sink: (PYFUNC_RE.exec(text)?.[1]) || 'PyFunc',
      message:
        'This SavedModel\'s graph contains a PyFunc/EagerPyFunc op, which invokes a Python callback during execution - a code-execution surface. It is sometimes benign (tf.py_function preprocessing), but in an untrusted pretrained model it is a way to run Python at inference/load time.',
      remediation:
        'Confirm why a distributed model needs a Python-callback op. Prefer a model whose graph is pure TF ops; load untrusted SavedModels only in a sandbox.',
      cwe: 'CWE-94',
    }));
  }
  if (WRITEFILE_RE.test(text)) {
    findings.push(finding({
      ruleId: 'savedmodel.file_write',
      title: 'TF SavedModel writes files during graph execution',
      severity: 'MEDIUM',
      file,
      sink: 'WriteFile',
      message:
        'This SavedModel\'s graph contains a WriteFile op - the model writes to the filesystem when run. In a pretrained model this is unusual and can be used to drop files during inference/load.',
      remediation: 'Review why the graph writes files. Load untrusted SavedModels only in a sandbox with no sensitive filesystem access.',
      cwe: 'CWE-73',
    }));
  }

  const sawTf =
    /serving_default|StatefulPartitionedCall|VarHandleOp|NoOp|Placeholder|saved_model_main_op|tf_saved_model|tensorflow|keras_version|["']class_name["']/.test(
      text,
    );

  const parses = looksLikeProtobuf(buf);
  return {
    findings,
    blindSpot: findings.length === 0 && !sawTf && !parses,
    notApplicable: findings.length === 0 && !sawTf && parses,
  };
}

export const SAVEDMODEL_SCAN_EXTS = ['.pb'];

export function isSavedModelScannable(path        )          {
  const p = path.toLowerCase();

  return p.endsWith('.pb') || p.endsWith('saved_model.pbtxt') || p.endsWith('keras_metadata.pb');
}
