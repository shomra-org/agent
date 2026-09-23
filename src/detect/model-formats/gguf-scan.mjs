// GENERATED MIRROR of Dragox.Backend model-formats/scanners/gguf-scan.ts (types stripped, imports swapped).
// Do not hand-edit - change the backend file and run scripts/mirror-model-config.mjs,
// so `shomra model-scan <path>` and the platform read a weight file identically.
import { inspectText } from '../signals/inspect-shim.mjs';
import { scanChatTemplate } from '../signals/chat-template.mjs';
const GGUF_MAGIC = 0x46554747;
const GgufType = {
    UINT8: 0,
    INT8: 1,
    UINT16: 2,
    INT16: 3,
    UINT32: 4,
    INT32: 5,
    FLOAT32: 6,
    BOOL: 7,
    STRING: 8,
    ARRAY: 9,
    UINT64: 10,
    INT64: 11,
    FLOAT64: 12
};
const MAX_KV = 4096;
const MAX_STRING = 1_000_000;
const MAX_ARRAY = 1_000_000;
const MAX_SCAN_BYTES = 8 * 1024 * 1024;
class Reader {
    buf;
    limit;
    offset = 0;
    constructor(buf, limit){
        this.buf = buf;
        this.limit = limit;
    }
    need(n) {
        if (n < 0 || this.offset + n > Math.min(this.buf.length, this.limit)) throw new Error('gguf: truncated');
    }
    u32() {
        this.need(4);
        const v = this.buf.readUInt32LE(this.offset);
        this.offset += 4;
        return v;
    }
    u64() {
        this.need(8);
        const v = this.buf.readBigUInt64LE(this.offset);
        this.offset += 8;
        if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('gguf: implausible length');
        return Number(v);
    }
    skip(n) {
        this.need(n);
        this.offset += n;
    }
    str() {
        const len = this.u64();
        if (len > MAX_STRING) throw new Error('gguf: oversized string');
        this.need(len);
        const s = this.buf.toString('utf8', this.offset, this.offset + len);
        this.offset += len;
        return s;
    }
}
const SCALAR_WIDTH = {
    [GgufType.UINT8]: 1,
    [GgufType.INT8]: 1,
    [GgufType.UINT16]: 2,
    [GgufType.INT16]: 2,
    [GgufType.UINT32]: 4,
    [GgufType.INT32]: 4,
    [GgufType.FLOAT32]: 4,
    [GgufType.BOOL]: 1,
    [GgufType.UINT64]: 8,
    [GgufType.INT64]: 8,
    [GgufType.FLOAT64]: 8
};
export function isGguf(buf) {
    return buf.length >= 4 && buf.readUInt32LE(0) === GGUF_MAGIC;
}
export function parseGgufMetadata(buf) {
    if (!isGguf(buf)) return null;
    const r = new Reader(buf, MAX_SCAN_BYTES);
    const strings = {};
    let version = 0;
    let tensorCount = 0;
    let truncated = false;
    try {
        r.skip(4);
        version = r.u32();
        tensorCount = r.u64();
        const kvCount = r.u64();
        const n = Math.min(kvCount, MAX_KV);
        if (kvCount > MAX_KV) truncated = true;
        for(let i = 0; i < n; i++){
            const key = r.str();
            const type = r.u32();
            if (type === GgufType.STRING) {
                strings[key] = r.str();
                continue;
            }
            if (type === GgufType.ARRAY) {
                const elem = r.u32();
                const count = r.u64();
                if (count > MAX_ARRAY) throw new Error('gguf: oversized array');
                if (elem === GgufType.STRING) {
                    for(let j = 0; j < count; j++)r.str();
                } else {
                    const w = SCALAR_WIDTH[elem];
                    if (w === undefined) throw new Error('gguf: unknown array element type');
                    r.skip(w * count);
                }
                continue;
            }
            const w = SCALAR_WIDTH[type];
            if (w === undefined) throw new Error('gguf: unknown value type');
            r.skip(w);
        }
    } catch  {
        truncated = true;
    }
    return {
        version,
        tensorCount,
        strings,
        truncated
    };
}
const CHAT_TEMPLATE_KEY = /^tokenizer\.chat_template(\.[A-Za-z0-9_-]+)?$/;
export function chatTemplateKeys(strings) {
    const keys = Object.keys(strings).filter((k)=>CHAT_TEMPLATE_KEY.test(k));
    return keys.length ? keys.sort() : [
        'tokenizer.chat_template'
    ];
}
const INSTRUCTION_KEYS = [
    'general.description'
];
const GGUF_RULE_ID = {
    'chat_template.ssti': 'gguf.chat_template_ssti',
    'chat_template.injection': 'gguf.metadata_injection',
    'chat_template.loader': 'gguf.chat_template_loader'
};
const finding = (f)=>({
        line: 1,
        snippetStartLine: 1,
        snippet: '',
        sink: '',
        ...f
    });
export function scanGgufModel(buf, file) {
    const metadata = parseGgufMetadata(buf);
    if (!metadata) return {
        findings: [],
        metadata: null
    };
    const findings = [];
    for (const key of chatTemplateKeys(metadata.strings)){
        for (const h of scanChatTemplate(metadata.strings[key] ?? '', file, {
            sink: key,
            renderer: 'llama.cpp, Ollama and LM Studio'
        })){
            findings.push({
                ...h,
                ruleId: GGUF_RULE_ID[h.ruleId] ?? h.ruleId
            });
        }
    }
    for (const key of INSTRUCTION_KEYS){
        const text = metadata.strings[key];
        if (!text) continue;
        const res = inspectText(text);
        const signals = res.matches.filter((m)=>m.category === 'injection');
        if (!signals.length) continue;
        findings.push(finding({
            ruleId: 'gguf.metadata_injection',
            title: `Injected instructions in GGUF metadata (${key})`,
            severity: 'HIGH',
            file,
            sink: key,
            snippet: text.slice(0, 600),
            message: `The GGUF metadata key \`${key}\` contains injected instructions. This text is prepended to every ` + 'conversation before the user says anything, so it acts as a system prompt the user cannot see or ' + 'override - a backdoored model needs no further exploit to exfiltrate or misbehave. Signals: ' + signals.map((m)=>m.label).slice(0, 4).join('; '),
            remediation: `Do not load this model. Inspect ${key} and obtain the model from a trusted publisher; re-convert from ` + 'the original weights if you need this architecture.',
            cwe: 'CWE-94',
            category: 'agentic',
            confidence: 0.85
        }));
    }
    return {
        findings,
        metadata
    };
}
