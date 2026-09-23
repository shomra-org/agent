// GENERATED MIRROR of Dragox.Backend model-formats/model-format.ts (types stripped, imports swapped).
// Do not hand-edit - change the backend file and run scripts/mirror-model-config.mjs,
// so `shomra model-scan <path>` and the platform read a weight file identically.
import { CODE_BEARING_FORMATS,                   } from './weight-formats.mjs';

export { CODE_BEARING_FORMATS,                   } from './weight-formats.mjs';

const MAGICS                                              = [
  { format: 'zip', magic: [0x50, 0x4b, 0x03, 0x04] },
  { format: 'hdf5', magic: [0x89, 0x48, 0x44, 0x46, 0x0d, 0x0a, 0x1a, 0x0a] },
  { format: 'npy', magic: [0x93, 0x4e, 0x55, 0x4d, 0x50, 0x59] },
  { format: 'gguf', magic: [0x47, 0x47, 0x55, 0x46] },
  { format: '7z', magic: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c] },
  { format: 'rar', magic: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07] },
  { format: 'gzip', magic: [0x1f, 0x8b] },
  { format: 'bzip2', magic: [0x42, 0x5a, 0x68] },
  { format: 'xz', magic: [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00] },
  { format: 'zstd', magic: [0x28, 0xb5, 0x2f, 0xfd] },
];

function hasMagic(buf        , magic          )          {
  if (buf.length < magic.length) return false;
  for (let i = 0; i < magic.length; i++) if (buf[i] !== magic[i]) return false;
  return true;
}

const MAX_SAFETENSORS_HEADER = 100 * 1024 * 1024;

export function safetensorsHeaderLength(buf        )                {
  if (buf.length < 9) return null;
  const big = buf.readBigUInt64LE(0);
  if (big <= 0n || big > BigInt(MAX_SAFETENSORS_HEADER)) return null;
  const len = Number(big);

  if (buf[8] !== 0x7b) return null;
  return len;
}

function isTar(buf        )          {
  return buf.length >= 265 && buf.toString('latin1', 257, 262) === 'ustar';
}

export function detectWeightFormat(buf        )               {
  if (!buf || buf.length < 2) return 'unknown';

  if (buf[0] === 0x80 && buf[1] >= 2 && buf[1] <= 5) return 'pickle';
  for (const { format, magic } of MAGICS) if (hasMagic(buf, magic)) return format;
  if (safetensorsHeaderLength(buf) !== null) return 'safetensors';
  if (isTar(buf)) return 'tar';
  return 'unknown';
}

const INERT_EXT                               = {
  '.safetensors': 'safetensors',
  '.gguf': 'gguf',
  '.npz': 'zip',
};

const ONNX_EXT = /\.onnx$/i;

export function extOf(path        )         {
  const i = path.lastIndexOf('.');
  return i === -1 ? '' : path.slice(i).toLowerCase();
}

                                 
               

                                  

                       

                       
 

export function detectFormatMismatch(path        , buf        )                        {
  const actual = detectWeightFormat(buf);
  if (actual === 'unknown') return null;

  if (ONNX_EXT.test(path)) {
    return CODE_BEARING_FORMATS.has(actual) ? { path, declared: 'onnx', actual, codeBearing: true } : null;
  }

  const declared = INERT_EXT[extOf(path)];
  if (!declared) return null;
  if (declared === actual) return null;

  if (declared === 'zip' && actual === 'zip') return null;
  if (!CODE_BEARING_FORMATS.has(actual)) return null;
  return { path, declared, actual, codeBearing: true };
}

export const FORMAT_LABEL                                        = {
  pickle: 'a raw Python pickle stream',
  zip: 'a ZIP container (a PyTorch checkpoint, Keras v3 archive or .npz)',
  safetensors: 'a safetensors file',
  gguf: 'a GGUF file',
  hdf5: 'an HDF5/Keras model file',
  npy: 'a NumPy .npy array',
  '7z': 'a 7-Zip archive',
  rar: 'a RAR archive',
  gzip: 'a gzip stream',
  bzip2: 'a bzip2 stream',
  xz: 'an xz stream',
  zstd: 'a zstd stream',
  tar: 'a tar archive',
  onnx: 'an ONNX model',
  unknown: 'an unidentified binary',
};
