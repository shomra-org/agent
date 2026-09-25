// GENERATED MIRROR of Dragox.Backend discovery/bundle/domain/memory/memory-locations.ts (types stripped, imports swapped).
// Do not hand-edit the rules here - change the backend file and regenerate, so
// the CLI and the platform locate and grade agent memory identically.
                                                                                     

                                                                   

                          
                 
                 
 

                                 
             
                 
             
                            
                      
                    
                         
 

                                  
             
                 
                       
                            
                     
                          
                        
 

const CLAUDE_INDEX_CAP          = { lines: 200, bytes: 25_000 };

export const MEMORY_LOCATIONS                   = [
  { id: 'claude-auto-memory-index', vendor: 'Claude Code', re: /(^|\/)\.claude\/projects\/[^/]+\/memory\/memory\.md$/, injected: 'always', loadCap: CLAUDE_INDEX_CAP },
  { id: 'claude-auto-memory', vendor: 'Claude Code', re: /(^|\/)\.claude\/projects\/[^/]+\/memory\/[^/]+\.md$/, injected: 'on-demand', claudeSchema: true },
  { id: 'claude-agent-memory-index', vendor: 'Claude Code', re: /(^|\/)\.claude\/agent-memory(-local)?\/[^/]+\/memory\.md$/, injected: 'always', committed: true, loadCap: CLAUDE_INDEX_CAP },
  { id: 'claude-agent-memory', vendor: 'Claude Code', re: /(^|\/)\.claude\/agent-memory(-local)?\/[^/]+\/.+\.md$/, injected: 'on-demand', committed: true },
  { id: 'claude-legacy-memory', vendor: 'Claude Code', re: /(^|\/)\.claude\/(.+\/)?memor(y|ies)\/.+\.(md|json|jsonl|txt)$/, injected: 'on-demand' },
  { id: 'codex-memory-summary', vendor: 'OpenAI Codex', re: /(^|\/)\.codex\/memories\/memory_summary\.md$/, injected: 'always' },
  { id: 'codex-memories', vendor: 'OpenAI Codex', re: /(^|\/)\.codex\/memories\/.+\.md$/, injected: 'on-demand' },
  { id: 'agents-sdk-memories', vendor: 'OpenAI Agents SDK', re: /(^|\/)memories\/(memory_summary\.md|raw_memories\/.+\.md|rollout_summaries\/.+\.md)$/, injected: 'always' },
  { id: 'gemini-memory', vendor: 'Gemini CLI', re: /(^|\/)\.gemini\/(tmp\/[^/]+\/)?(memory\.md|memor(y|ies)\/.+\.md)$/, injected: 'always' },
  { id: 'qwen-auto-memory', vendor: 'Qwen Code', re: /(^|\/)\.qwen\/projects\/[^/]+\/memory\/.+\.md$/, injected: 'always' },
  { id: 'qwen-team-memory', vendor: 'Qwen Code', re: /(^|\/)\.qwen\/team-memory\/.+\.(md|txt)$/, injected: 'always', committed: true },
  { id: 'windsurf-memories', vendor: 'Windsurf', re: /(^|\/)\.codeium\/(windsurf|windsurf-next)\/memories\/(?!global_rules\.md$)[^/]+$/, injected: 'retrieved' },
  { id: 'copilot-memory-tool', vendor: 'GitHub Copilot (VS Code)', re: /(^|\/)(globalstorage|workspacestorage\/[^/]+)\/github\.copilot-chat\/memory-tool\/.+\.(md|txt|json)$/, injected: 'always' },
  { id: 'vscode-memories', vendor: 'GitHub Copilot (VS Code)', re: /(^|\/)\.vscode\/memories\/.+\.md$/, injected: 'always' },
  { id: 'kilo-memory-bank', vendor: 'Kilo Code', re: /(^|\/)\.kilocode\/rules\/memory-bank\/.+\.md$/, injected: 'always', committed: true },
  { id: 'memory-bank', vendor: 'Cline / Roo Code', re: /(^|\/)memory-bank\/[^/]+\.md$/, injected: 'always', committed: true },
  { id: 'serena-memories', vendor: 'Serena MCP', re: /(^|\/)\.serena\/memories\/.+\.md$/, injected: 'on-demand', committed: true },
  { id: 'goose-memory', vendor: 'Goose', re: /(^|\/)(\.goose|\.config\/goose)\/memory\/.+\.(txt|md)$/, injected: 'always' },
  { id: 'basic-memory', vendor: 'basic-memory', re: /(^|\/)basic-memory\/.+\.md$/, injected: 'retrieved' },
  { id: 'mem0-local', vendor: 'mem0 / OpenMemory', re: /(^|\/)\.mem0\/.+$/, injected: 'retrieved' },
  { id: 'letta-local', vendor: 'Letta / MemGPT', re: /(^|\/)\.(letta|memgpt)\/.+$/, injected: 'retrieved' },
  { id: 'crewai-memory', vendor: 'CrewAI', re: /(^|\/)(\.crewai\/memory\/.+|long_term_memory_storage\.db)$/, injected: 'retrieved' },
  { id: 'openclaw-memory', vendor: 'OpenClaw', re: /(^|\/)\.openclaw\/(?:workspace\/)?(?:MEMORY\.md|SOUL\.md|HEARTBEAT\.md|memory\/[^/]+\.md)$/i, injected: 'always', committed: true },
  { id: 'mcp-server-memory', vendor: 'MCP memory server', re: /(^|\/)memory\.jsonl$/, injected: 'retrieved' },
  { id: 'vendor-memory-dir', vendor: 'Agent memory', re: /^(?!.*\/global_rules\.md$)(.*\/)?\.(cursor|continue|aider|windsurf|cline|roo|zed|codeium|kiro|junie|augment|amp|opencode|trae|codex|gemini|qwen|kilocode)\/(.+\/)?memor(y|ies)\/.+\.(md|mdx|mdc|json|jsonl|txt|ya?ml)$/, injected: 'on-demand' },
  { id: 'memory-tool-root', vendor: 'Anthropic memory tool', re: /^\/?memories\/.+\.(md|txt|xml|json)$/, injected: 'always' },
  { id: 'generic-memory-file', vendor: 'Agent memory', re: /(^|\/)(memor(y|ies)|agent[-_]memory|mem0|letta_memory|memgpt_memory)\.(md|mdx|json|jsonl|txt)$/, injected: 'always' },
  { id: 'generic-memory-dir', vendor: 'Agent memory', re: /^memor(y|ies)\/[^/]+\.(md|mdx|json|jsonl|txt|ya?ml)$/, injected: 'on-demand' },
];

export const MEMORY_SECTION_HEADINGS                                                          = [
  { vendor: 'Gemini CLI', basename: /^gemini(\.local)?\.md$/, heading: /^##\s+gemini added memories\s*$/im },
  { vendor: 'Qwen Code', basename: /^qwen(\.local)?\.md$/, heading: /^##\s+qwen added memories\s*$/im },
];

// ⚠ NOT DEAD CODE. Nothing in the backend reads the two tables below, but they
// are mirrored into Shomra.Agent (scripts/mirror-memory.mjs) where `shomra
// memory-scan` walks MACHINE_MEMORY_ROOTS and prints SERVER_SIDE_MEMORY. An
// unused-export sweep removed them once and the mirror bench caught it.
export const SERVER_SIDE_MEMORY                                     = [
  { vendor: 'ChatGPT', note: 'Saved memories live on OpenAI servers; nothing on disk to read.' },
  { vendor: 'GitHub Copilot Memory', note: 'Repository facts and preferences live on GitHub; only the VS Code memory tool is local.' },
  { vendor: 'Devin', note: 'Knowledge entries live in the Devin service.' },
  { vendor: 'Letta Code', note: 'Memory blocks live on the Letta API, not local files.' },
  { vendor: 'Cursor', note: 'Memories were removed in Cursor 2.1; exported memories become .cursor/rules files.' },
];

                                    
                 
                                           
              
                
 

export const MACHINE_MEMORY_ROOTS                      = [
  { vendor: 'Claude Code', base: 'home', dir: '.claude/projects/*/memory', depth: 1 },
  { vendor: 'Claude Code', base: 'home', dir: '.claude/agent-memory', depth: 3 },
  { vendor: 'Claude Code', base: 'home', dir: '.claude', depth: 1 },
  { vendor: 'OpenAI Codex', base: 'home', dir: '.codex/memories', depth: 3 },
  { vendor: 'OpenAI Codex', base: 'home', dir: '.codex', depth: 1 },
  { vendor: 'Gemini CLI', base: 'home', dir: '.gemini', depth: 4 },
  { vendor: 'Qwen Code', base: 'home', dir: '.qwen', depth: 4 },
  { vendor: 'Windsurf', base: 'home', dir: '.codeium/windsurf/memories', depth: 1 },
  { vendor: 'Windsurf', base: 'home', dir: '.codeium/windsurf-next/memories', depth: 1 },
  { vendor: 'Goose', base: 'home', dir: '.config/goose/memory', depth: 1 },
  { vendor: 'Serena MCP', base: 'home', dir: '.serena/memories', depth: 3 },
  { vendor: 'basic-memory', base: 'home', dir: 'basic-memory', depth: 4 },
  { vendor: 'mem0 / OpenMemory', base: 'home', dir: '.mem0', depth: 2 },
  { vendor: 'Letta / MemGPT', base: 'home', dir: '.letta', depth: 2 },
  { vendor: 'OpenClaw', base: 'home', dir: '.openclaw/workspace', depth: 3 },
  { vendor: 'GitHub Copilot (VS Code)', base: 'vscode-user', dir: 'globalStorage/github.copilot-chat/memory-tool', depth: 4 },
];

const BINARY_EXTS = new Set(['db', 'sqlite', 'sqlite3', 'pb', 'lance', 'bin', 'parquet', 'arrow', 'duckdb', 'ldb', 'sst', 'wal']);

export function normalizeMemoryPath(p        )         {
  return String(p ?? '').split(/[\\/]+/).join('/').toLowerCase();
}

export function memoryFormatForPath(p        )               {
  const lower = normalizeMemoryPath(p);
  const base = lower.slice(lower.lastIndexOf('/') + 1);
  const ext = base.includes('.') ? base.slice(base.lastIndexOf('.') + 1) : '';
  if (BINARY_EXTS.has(ext)) return 'binary';
  if (ext === 'jsonl' || ext === 'ndjson') return 'jsonl';
  if (ext === 'json') return 'json';
  if (ext === 'xml') return 'xml';
  if (ext === 'md' || ext === 'mdx' || ext === 'mdc') return 'markdown';
  if (ext === 'txt' || ext === 'yaml' || ext === 'yml' || ext === '') return 'text';
  return 'binary';
}

export function classifyMemoryPath(p        )                         {
  const lower = normalizeMemoryPath(p);
  if (!lower) return null;
  const loc = MEMORY_LOCATIONS.find((l) => l.re.test(lower));
  if (!loc) return null;
  return {
    id: loc.id,
    vendor: loc.vendor,
    format: memoryFormatForPath(lower),
    injected: loc.injected,
    committed: !!loc.committed,
    loadCap: loc.loadCap ?? null,
    claudeSchema: !!loc.claudeSchema,
  };
}

export function memorySectionFor(p        )                                             {
  const lower = normalizeMemoryPath(p);
  const base = lower.slice(lower.lastIndexOf('/') + 1);
  const hit = MEMORY_SECTION_HEADINGS.find((s) => s.basename.test(base));
  return hit ? { vendor: hit.vendor, heading: hit.heading } : null;
}

export function sniffMemoryJsonl(text                           )          {
  const first = String(text ?? '').split(/\r?\n/).find((l) => l.trim());
  if (!first || !first.trim().startsWith('{')) return false;
  try {
    const row = JSON.parse(first);
    return !!row && typeof row === 'object' && (row.type === 'entity' || row.type === 'relation') && ('observations' in row || 'relationType' in row || 'entityType' in row);
  } catch {
    return false;
  }
}
