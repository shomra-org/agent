// GENERATED MIRROR of Dragox.Backend model-formats/scanners/safetensors-scan.ts (types stripped, imports swapped).
// Do not hand-edit - change the backend file and run scripts/mirror-model-config.mjs,
// so `shomra model-scan <path>` and the platform read a weight file identically.
                                                                            
                                                        
import { inspectText } from '../signals/inspect-shim.mjs';
import { safetensorsHeaderLength } from './model-format.mjs';
const binaryFinding = () => (f) => f;

const MAX_HEADER_DECODE = 8 * 1024 * 1024;

const HEADER_RATIO_ALARM = 0.5;

const HEADER_RATIO_MIN_BYTES = 1024 * 1024;

                                    
                               

                                   

                      

                     
 

export function parseSafetensorsHeader(buf        )                           {
  const len = safetensorsHeaderLength(buf);
  if (len === null) return null;
  const end = 8 + len;
  if (len > MAX_HEADER_DECODE) return { tensors: {}, metadata: {}, headerBytes: len, truncated: true };
  if (end > buf.length) {
    return { tensors: {}, metadata: {}, headerBytes: len, truncated: true };
  }
  let parsed     ;
  try {
    parsed = JSON.parse(buf.toString('utf8', 8, end));
  } catch {
    return { tensors: {}, metadata: {}, headerBytes: len, truncated: true };
  }
  if (!parsed || typeof parsed !== 'object') return { tensors: {}, metadata: {}, headerBytes: len, truncated: true };

  const metadata                         = {};
  const raw = parsed.__metadata__;
  if (raw && typeof raw === 'object') {
    for (const [k, v] of Object.entries(raw)) if (typeof v === 'string') metadata[k] = v;
  }
  const tensors                      = { ...parsed };
  delete tensors.__metadata__;
  return { tensors, metadata, headerBytes: len, truncated: false };
}

export function parsesAsSafetensors(buf        )          {
  return safetensorsHeaderLength(buf) !== null;
}

const finding = binaryFinding('safetensors header', 'deserialization');

const DTYPE_BITS                         = {
  BOOL: 8, U8: 8, I8: 8, F8_E4M3: 8, F8_E5M2: 8,
  I16: 16, U16: 16, F16: 16, BF16: 16,
  I32: 32, U32: 32, F32: 32,
  I64: 64, U64: 64, F64: 64,
};

                      
               
                
              
                          
 

function tensorSpans(tensors                     )               {
  const spans               = [];
  for (const [name, spec] of Object.entries(tensors)) {
    const off = spec && (spec       ).data_offsets;
    if (!Array.isArray(off) || off.length !== 2) continue;
    const [begin, end] = off;
    if (!Number.isFinite(begin) || !Number.isFinite(end)) continue;
    const bits = DTYPE_BITS[String((spec       ).dtype ?? '').toUpperCase()];
    const shape = (spec       ).shape;
    let required                = null;
    if (bits && Array.isArray(shape) && shape.every((d     ) => Number.isInteger(d) && d >= 0)) {
      required = Math.ceil((shape.reduce((a        , b        ) => a * b, 1) * bits) / 8);
    }
    spans.push({ name, begin: Number(begin), end: Number(end), required });
  }
  return spans.sort((a, b) => a.begin - b.begin || a.end - b.end);
}

                               
                                                           
                 
 

export function offsetDefects(
  tensors                     ,
  dataBytes               ,
)                 {
  const spans = tensorSpans(tensors);
  const defects                 = [];
  for (let i = 0; i < spans.length; i++) {
    const t = spans[i];
    if (t.begin < 0 || t.end < t.begin) {
      defects.push({ kind: 'inverted', detail: `${t.name} spans [${t.begin}, ${t.end})` });
      continue;
    }
    const prev = spans[i - 1];
    if (prev && prev.end > t.begin && prev.end > prev.begin) {
      defects.push({ kind: 'overlap', detail: `${prev.name} [${prev.begin}, ${prev.end}) overlaps ${t.name} [${t.begin}, ${t.end})` });
    }
    if (dataBytes !== null && t.end > dataBytes) {
      defects.push({ kind: 'past-end', detail: `${t.name} ends at ${t.end}, past the ${dataBytes}-byte tensor block` });
    }
    if (t.required !== null && t.end - t.begin < t.required) {
      defects.push({ kind: 'undersized', detail: `${t.name} declares ${t.required} bytes of data in a ${t.end - t.begin}-byte span` });
    }
  }
  return defects;
}

const DEFECT_MEANING                                       = {
  inverted: 'a span whose end precedes its start',
  overlap: 'two tensors mapped onto the same bytes, so the name a reviewer inspects is not the buffer that loads',
  'past-end': 'a span running past the end of the tensor block, which reads memory the file does not contain',
  undersized: 'a span smaller than the shape and dtype it declares, which makes a loader read past it',
};

                                        
                          
                                   

                     
 

export function scanSafetensors(buf        , file        , declaredSize         )                        {
  const header = parseSafetensorsHeader(buf);
  if (!header) return { findings: [], header: null, blindSpot: true };

  const findings                = [];

  for (const [key, value] of Object.entries(header.metadata)) {
    if (!value || value.length < 12) continue;
    const signals = inspectText(value, { categories: ['injection'] }).matches;
    if (signals.length) {
      findings.push(
        finding({
          ruleId: 'safetensors.metadata_injection',
          title: `Injected instructions in safetensors metadata (${key})`,
          severity: 'HIGH',
          file,
          sink: `__metadata__.${key}`,
          snippet: value.slice(0, 600),
          message:
            `The safetensors header's \`__metadata__.${key}\` carries injected instructions. safetensors is inert ` +
            'as a tensor container, but this string is not tensor data - it survives conversion, model-card ' +
            'generators and catalog tooling read it, and an agent that ingests it is reading attacker text. ' +
            'Signals: ' +
            signals
              .map((m) => m.label)
              .slice(0, 4)
              .join('; '),
          remediation:
            `Strip \`__metadata__.${key}\` before use (safetensors.torch.save_file lets you set the metadata map ` +
            'explicitly), and do not feed model metadata into an agent context unreviewed.',
          cwe: 'CWE-94',
          confidence: 0.85,
        }),
      );
    }

    const secrets = inspectText(value, { categories: ['secret'] }).matches;
    if (secrets.length) {
      findings.push(
        finding({
          ruleId: 'safetensors.metadata_secret',
          title: `Credential in safetensors metadata (${key})`,
          severity: secrets[0].severity            ,
          file,
          sink: `__metadata__.${key}`,
          snippet: '(redacted)',
          message:
            `A credential-shaped value (${secrets[0].sample}) is stored in the safetensors header under ` +
            `\`__metadata__.${key}\`. Anyone who downloads the weights can read it - the header is the first ` +
            'few kilobytes of the file and needs no special tooling.',
          remediation: 'Revoke the credential and republish the weights with the metadata map cleaned.',
          cwe: 'CWE-798',
          confidence: 0.9,
        }),
      );
    }
  }

  const dataBytes =
    declaredSize && declaredSize > 8 + header.headerBytes ? declaredSize - 8 - header.headerBytes : null;
  const defects = header.truncated ? [] : offsetDefects(header.tensors, dataBytes);
  if (defects.length) {
    const kinds = [...new Set(defects.map((d) => d.kind))];
    findings.push(
      finding({
        ruleId: 'safetensors.offset_table',
        title: 'safetensors offset table does not describe this file',
        severity: 'HIGH',
        file,
        sink: 'header.data_offsets',
        snippet: defects.slice(0, 4).map((d) => d.detail).join('; '),
        message:
          `The header's tensor offset table is inconsistent: ${kinds.map((k) => DEFECT_MEANING[k]).join('; ')}. ` +
          'A safetensors file is trusted precisely because the header is the only thing a loader interprets, and ' +
          'the writer emits contiguous, correctly sized, non-overlapping spans. A header that does not is either ' +
          'corrupt or hand-built, and hand-built offset tables are how a loader that does not bound-check its ' +
          `reads is made to return memory beyond the tensor block. ${defects.length} defect(s); first: ` +
          defects[0].detail + '.',
        remediation:
          'Do not load this file. Re-save the tensors with safetensors.torch.save_file from the original weights, ' +
          'and compare the resulting offset table against the one shipped here.',
        cwe: 'CWE-125',
        confidence: 0.9,
      }),
    );
  }

  const total = Number(declaredSize ?? 0);
  if (
    header.headerBytes >= HEADER_RATIO_MIN_BYTES &&
    total > 0 &&
    header.headerBytes / total >= HEADER_RATIO_ALARM
  ) {
    findings.push(
      finding({
        ruleId: 'safetensors.oversized_header',
        title: 'safetensors header is most of the file',
        severity: 'MEDIUM',
        file,
        sink: 'header',
        snippet: `header: ${header.headerBytes} bytes of ${total} total`,
        message:
          `This file's JSON header is ${Math.round((header.headerBytes / total) * 100)}% of its total size ` +
          `(${Math.round(header.headerBytes / 1024)} KB of ${Math.round(total / 1024)} KB). A safetensors header ` +
          'describes tensor names, shapes and offsets and is normally a rounding error against the payload; a ' +
          'header this large is carrying something that is not tensor bookkeeping, and the file listing shows ' +
          'only a total size, so nothing else would reveal it.',
        remediation:
          'Inspect the header JSON directly (the first 8 bytes are its little-endian length). Re-save the tensors ' +
          'with an explicit metadata map if the content is unwanted.',
        cwe: 'CWE-912',
        confidence: 0.75,
      }),
    );
  }

  return { findings, header, blindSpot: header.truncated };
}

export const SAFETENSORS_SCAN_EXTS = ['.safetensors'];

