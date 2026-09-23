// GENERATED MIRROR of Dragox.Backend shared/kernel/supply/weight-formats.ts (types stripped, imports swapped).
// Do not hand-edit - change the backend file and run scripts/mirror-model-config.mjs,
// so `shomra model-scan <path>` and the platform read a weight file identically.
/**
 * Serialized-model container formats as the magic-byte detector names them, and
 * which of them can run code on load. Shared so the gate's `model-file` policy
 * subject and the detector (analysis/…/model-format.ts re-exports these) agree on
 * what "code-bearing" means - GGUF included: its Jinja chat template is rendered
 * by the loader.
 */
                          

            

         

                 

          

          

         

        
         
          
           
        
          
         

              

export const CODE_BEARING_FORMATS                            = new Set              ([
  'pickle',
  'zip',
  'hdf5',
  'npy',
  'gguf',
  '7z',
  'rar',
  'gzip',
  'bzip2',
  'xz',
  'zstd',
  'tar',
]);
