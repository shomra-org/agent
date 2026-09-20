import { parseYaml } from '../../core/yaml-lite.mjs';
import { aiStepOf, ciVendorOf,                            } from './ci-model.mjs';

export { CI_PATH_RE, aiStepOf, ciVendorOf,                                             } from './ci-model.mjs';

const MAX_JOBS = 100;
const MAX_STEPS = 200;
const obj = (v         )                             => (v && typeof v === 'object' && !Array.isArray(v) ? (v                       ) : null);
const text = (v         )         => (v == null ? '' : typeof v === 'string' ? v : typeof v === 'object' ? safeJson(v) : String(v));
function safeJson(v         )         {
  try { return JSON.stringify(v) ?? ''; } catch { return ''; }
}
const strMap = (v         )                         =>
  Object.fromEntries(Object.entries(obj(v) ?? {}).slice(0, 200).map(([k, x]) => [k, text(x)]));

function githubTriggers(on         )           {
  if (typeof on === 'string') return [on];
  if (Array.isArray(on)) return on.map(String);
  return Object.keys(obj(on) ?? {});
}

function readGithub(doc                     )                                        {

  const triggers = githubTriggers(doc.on ?? doc.true ?? doc['"on"']).slice(0, 40);
  const wfEnv = strMap(doc.env);
  const jobs          = [];
  const addJob = (id        , j                     ) => {
    const jobEnv = strMap(j.env);
    const steps           = [];
    for (const [index, raw] of (Array.isArray(j.steps) ? j.steps : []).slice(0, MAX_STEPS).entries()) {
      const s = obj(raw);
      if (!s) continue;
      const uses = typeof s.uses === 'string' ? s.uses.trim() : null;
      const run = typeof s.run === 'string' ? s.run : null;
      const w = strMap(s.with);
      const env = strMap(s.env);
      steps.push({
        job: id, index, id: typeof s.id === 'string' ? s.id : null, uses, run, with: w, env,
        if: s.if == null ? null : text(s.if),
        ai: aiStepOf(uses, run ?? (w.script || null)),

        inputText: [run ?? '', ...Object.entries(w).map(([k, v]) => `${k}: ${v}`), ...Object.values(env), ...Object.values(jobEnv), ...Object.values(wfEnv)].join('\n'),
      });
    }
    jobs.push({ id, if: j.if == null ? null : text(j.if), permissions: j.permissions, steps });
  };
  for (const [id, j] of Object.entries(obj(doc.jobs) ?? {}).slice(0, MAX_JOBS)) if (obj(j)) addJob(id, j);

  const runs = obj(doc.runs);
  if (runs && Array.isArray(runs.steps)) addJob('composite', runs);
  return { triggers, permissions: doc.permissions, jobs };
}

function readScripted(vendor          , src        , doc                            )                                        {
  const scripts                                 = [];
  const visit = (node         , job        , depth        ) => {
    if (depth > 12 || scripts.length > MAX_STEPS) return;
    if (Array.isArray(node)) { for (const x of node) visit(x, job, depth + 1); return; }
    const o = obj(node);
    if (!o) return;
    for (const [k, v] of Object.entries(o)) {
      if (/^(script|before_script|after_script|command|commands|run|bash|powershell|pwsh|inline_?script)$/i.test(k)) {
        for (const line of Array.isArray(v) ? v : [v]) if (typeof line === 'string' || obj(line)) scripts.push({ job, run: typeof line === 'string' ? line : text(line) });
      } else visit(v, depth === 0 ? k : job, depth + 1);
    }
  };
  if (doc) visit(doc, 'pipeline', 0);
  else scripts.push({ job: 'pipeline', run: src });
  const triggers =
    vendor === 'gitlab' ? (/merge_request_event|\$CI_MERGE_REQUEST_/.test(src) ? ['merge_request'] : ['push'])
      : vendor === 'azure' ? (doc && 'pr' in doc ? ['pr'] : ['push'])
        : vendor === 'bitbucket' ? (/pull-requests\s*:/.test(src) ? ['pull-requests'] : ['push'])
          : ['push'];
  const jobs = new Map               ();
  for (const s of scripts) {
    const job = jobs.get(s.job) ?? { id: s.job, if: null, permissions: undefined, steps: [] };
    jobs.set(s.job, job);
    job.steps.push({ job: s.job, index: job.steps.length, id: null, uses: null, run: s.run, with: {}, env: {}, if: null, ai: aiStepOf(null, s.run), inputText: s.run });
  }
  return { triggers, permissions: undefined, jobs: [...jobs.values()].slice(0, MAX_JOBS) };
}

export function ciWorkflowModel(path        , src        )                    {
  const vendor = ciVendorOf(path);
  if (!vendor) return null;
  if (vendor === 'jenkins') return { vendor, parsed: false, ...readScripted(vendor, src, null) };
  const doc = obj(parseYaml(src));
  if (!doc) return { vendor, parsed: false, ...readScripted(vendor, src, null) };
  return { vendor, parsed: true, ...(vendor === 'github' ? readGithub(doc) : readScripted(vendor, src, doc)) };
}

export const PRIVILEGED_UNTRUSTED_TRIGGERS = new Set([
  'issue_comment', 'issues', 'pull_request_target', 'discussion', 'discussion_comment', 'workflow_run',
]);

export const UNPRIVILEGED_UNTRUSTED_TRIGGERS = new Set([
  'pull_request', 'pull_request_review', 'pull_request_review_comment', 'merge_request', 'pr', 'pull-requests',
]);

const EXPRESSION_RE = /\$\{\{([^}]{1,400})\}\}/g;
const UNTRUSTED_BODY_RE =
  /\bgithub\.event\.(?:issue|comment|pull_request|discussion|review|review_comment|head_commit|workflow_run)\b[\w.*[\]]{0,120}\.(?:body|title|message|label|name|ref|head_branch|display_title|default_branch|email)\b|\bgithub\.event\.(?:commits|pages)\b|\bgithub\.head_ref\b|\btoJSON\(\s*github\.event\s*(?:\.\s*(?:issue|comment|pull_request|discussion|review)\s*)?\)/i;
const WRITER_BODY_RE = /\b(?:inputs|github\.event\.inputs)\.[\w-]+/;
const CI_VARIABLE_RE =
  /\$\{?CI_(?:MERGE_REQUEST_(?:TITLE|DESCRIPTION|SOURCE_BRANCH_NAME)|COMMIT_(?:MESSAGE|TITLE|DESCRIPTION|REF_NAME|BRANCH))\b\}?|\$\((?:System\.PullRequest\.(?:SourceBranch|Title|Description)|Build\.SourceVersionMessage)\)/g;

function expressions(src        , body        )           {
  const out = new Set        ();
  for (const m of src.slice(0, 2_000_000).matchAll(EXPRESSION_RE)) {
    if (body.test(m[1])) out.add(m[0]);
    if (out.size >= 20) break;
  }
  return [...out];
}

export function untrustedRefs(src                           )           {
  if (!src) return [];
  return [...new Set([...expressions(src, UNTRUSTED_BODY_RE), ...(src.slice(0, 2_000_000).match(CI_VARIABLE_RE) ?? [])])].slice(0, 20);
}

export function writerRefs(src                           )           {
  return src ? expressions(src, WRITER_BODY_RE) : [];
}

export const ACTOR_GATE_RE =
  /author_association|github\.(?:triggering_)?actor\b|github\.event\.sender\.login|\.labels\.\*\.name|github\.event\.label\.name|head\.repo\.fork\s*==\s*false|head\.repo\.full_name\s*==\s*github\.repository|getCollaboratorPermissionLevel|permission(?:-level)?\s*==\s*['"](?:admin|write|maintain)/i;
export const PERMISSION_CHECK_ACTION_RE = /check-(?:user-)?permission|check-actor-permission|actor-permission|user-permission/i;

export const MODEL_SECRET_RE = /^(?:ANTHROPIC_API_KEY|CLAUDE_CODE_OAUTH_TOKEN|OPENAI_API_KEY|OPENAI_KEY|GEMINI_API_KEY|GOOGLE_API_KEY|GOOGLE_GENERATIVE_AI_API_KEY|AZURE_OPENAI_(?:API_)?KEY|MISTRAL_API_KEY|GROQ_API_KEY|OPENROUTER_API_KEY|GITHUB_TOKEN|DEEPSEEK_API_KEY|XAI_API_KEY|DASHSCOPE_API_KEY)$/i;

