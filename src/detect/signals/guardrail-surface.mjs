import {
  guardrailFramework, guardrailModel, isCleartextRemote,

} from './guardrail-shape.mjs';
import { locate } from './agentic-shim.mjs';
import { textFindings } from './agentic-shim.mjs';

const FRAMEWORK_LABEL                                     = {
  nemo: 'NeMo Guardrails', colang: 'Colang', 'guardrails-ai': 'Guardrails AI', bedrock: 'Bedrock Guardrails',
  'azure-rai': 'Azure OpenAI content filter', litellm: 'LiteLLM guardrail', portkey: 'Portkey guardrail',
  'llm-guard': 'LLM Guard', kong: 'Kong AI plugin',
};
const MAX_CONTROL_FINDINGS = 12;

function controlFinding(a                  , fw        , c              )                  {
  const sev                              =
    c.state === 'weak' ? (c.injection ? 'MEDIUM' : 'LOW') : c.injection ? 'HIGH' : 'MEDIUM';
  const verb = c.state === 'disabled' ? 'is switched off' : c.state === 'observe-only' ? (c.validator ? 'returns the value the validator rejected' : 'records failures and blocks nothing') : 'is set too permissive to fire';
  const what = c.injection ? 'This is the control a prompt-injection or jailbreak attempt has to get past' : 'The control is listed as configured';
  return {
    class: 'MISSING_CONTROL',
    severity: sev,
    title: `${fw} "${c.name}" ${verb}`,
    detail:
      `${c.why ? `${c.why}. ` : ''}${what}, and every inventory that counts configured guardrails counts this one - ` +
      (c.state === 'observe-only'
        ? 'but a failed check hands the original input or output on unchanged, so the log says it fired and the user sees what it objected to.'
        : c.state === 'disabled'
          ? 'but it inspects nothing.'
          : 'but at this setting it only catches what is already unmistakable, which is not what a working attack looks like.'),
    remediationText:
      c.state === 'observe-only'
        ? 'Switch the action to one that changes the outcome (block / deny / exception / filter) for any control whose job is to stop something; keep log-only for controls you are deliberately measuring, and label them as such.'
        : c.state === 'disabled'
          ? 'Enable the control, or remove it so the configuration states what is actually screened.'
          : 'Restore the threshold or strength to the vendor default (or stricter) and measure the false-positive cost before loosening it again.',
    remediationTier: c.injection ? 1 : 2,
    evidence: { control: c.name, direction: c.direction, state: c.state, why: c.why, injection: c.injection, path: a.path, ...locate(c.anchor, a.content) },
  };
}

function coverageFindings(a                  , fw        , m                )                    {
  const out                    = [];
  if (m.emptyRails.length) {
    out.push({
      class: 'MISSING_CONTROL',
      severity: 'HIGH',
      title: `Guardrail config "${a.name}" declares a rail that screens nothing`,
      detail:
        `The ${m.emptyRails.join(' and ')} rail${m.emptyRails.length === 1 ? ' is' : 's are'} declared with an empty \`flows\` list. A declared rail with no flows is not an absent control - it is a configured one that passes everything through, so the deployment reports guardrails as enabled while nothing inspects that side.` +
        (m.declaredRails.length ? ` The ${m.declaredRails.join(', ')} rail${m.declaredRails.length === 1 ? '' : 's'} do carry flows, which is what makes the empty one read as an oversight rather than a decision.` : ''),
      remediationText: 'Populate the rail with the flows it needs (a self-check, a jailbreak detector, a fact-check) or remove the key, so the configuration says what is actually screened.',
      remediationTier: 1,
      evidence: { emptyRails: m.emptyRails, declaredRails: m.declaredRails, path: a.path, ...locate('flows', a.content) },
    });
  }
  if (m.streamedBeforeCheck) {
    out.push({
      class: 'MISSING_CONTROL',
      severity: 'MEDIUM',
      title: `${fw} "${a.name}" streams the answer before the output check runs`,
      detail: `${m.streamedBeforeCheck.why}. The user receives each chunk first and the output control judges it afterwards, so a response it would have blocked - leaked data, a policy breach - has already been displayed when the verdict arrives. The control can end the stream; it cannot un-send it.`,
      remediationText: 'Buffer output until the check passes (NeMo: `stream_first: false`; Azure: a blocking / default filter mode) for any deployment where the output rail is meant to prevent disclosure rather than record it.',
      remediationTier: 2,
      evidence: { why: m.streamedBeforeCheck.why, path: a.path, ...locate(m.streamedBeforeCheck.anchor, a.content) },
    });
  }
  for (const o of m.optIn.slice(0, 6)) {
    out.push({
      class: 'MISSING_CONTROL',
      severity: 'MEDIUM',
      title: `${fw} "${o.name}" runs only when the caller asks for it`,
      detail: '`default_on` is not true, so the guardrail applies only to requests (or keys / teams) that name it. A caller that simply omits it - including any client an attacker controls - gets the model with no screening, while the guardrail still appears in the proxy\'s configuration.',
      remediationText: 'Set `default_on: true` for any guardrail meant to protect every request, and attach opt-in guardrails to keys or teams explicitly so the exemption is visible.',
      remediationTier: 1,
      evidence: { guardrail: o.name, path: a.path, ...locate(o.anchor, a.content) },
    });
  }
  for (const f of m.failOpen.slice(0, 6)) {
    out.push({
      class: 'MISSING_CONTROL',
      severity: 'MEDIUM',
      title: `${fw} "${f.name}" fails open`,
      detail: `${f.why}. When the guardrail service is slow, down or rate-limited, requests reach the model unscreened - and a caller who can make the check error (an oversized or malformed payload) chooses when that happens.`,
      remediationText: 'Fail closed for controls that are meant to block; alert on guardrail errors instead of absorbing them.',
      remediationTier: 2,
      evidence: { guardrail: f.name, why: f.why, path: a.path, ...locate(f.anchor, a.content) },
    });
  }
  for (const b of m.blindSpots.slice(0, 6)) {
    const minor = /match_all_roles/.test(b.why);
    out.push({
      class: 'MISSING_CONTROL',
      severity: minor ? 'LOW' : 'MEDIUM',
      title: `${fw} "${b.name}" does not look at part of the conversation`,
      detail: `${b.why}. An instruction placed where the control does not look passes it untouched and still reaches the model in full.`,
      remediationText: 'Screen every message the model receives - all turns, all roles and tool results - or state the gap so another control covers it.',
      remediationTier: 2,
      evidence: { guardrail: b.name, why: b.why, path: a.path, ...locate(b.anchor, a.content) },
    });
  }
  return out;
}

function judgeFindings(a                  , fw        , m                )                    {
  const out                    = [];
  for (const p of m.judgePrompts.slice(0, 20)) {
    if (p.missingVars.length) {
      out.push({
        class: 'MISSING_CONTROL',
        severity: 'HIGH',
        title: `${fw} judge prompt "${p.task}" never receives the text it judges`,
        detail: `The ${p.task} template has no {{ ${p.missingVars.join(' }}/{{ ')} }} placeholder, so the judge model is asked the same fixed question on every call and gives the same verdict whatever the user sent. The rail runs, costs a model call, and screens nothing.`,
        remediationText: `Include {{ ${p.missingVars[0]} }} in the ${p.task} prompt, inside clear delimiters, and test the rail against a known-bad input.`,
        remediationTier: 1,
        evidence: { task: p.task, missingVars: p.missingVars, path: a.path, ...locate(p.task, a.content) },
      });
    }
    for (const f of textFindings(a, p.content, 'PROMPT_INJECTION').filter((x) => x.class === 'PROMPT_INJECTION')) {
      out.push({
        ...f,
        severity: 'CRITICAL',
        title: `Injected directive in the guardrail's own judge prompt (${p.task})`,
        detail: `${f.detail} This text is the prompt the ${p.task} check sends to its judge model, so a directive here does not bypass one answer - it rewrites the instructions of the control that screens every answer, and the rail keeps reporting that it ran.`,
        evidence: { ...(f.evidence ?? {}), task: p.task, surface: 'guardrail-judge-prompt', path: a.path },
      });
    }
  }
  for (const task of [...new Set(m.missingPrompts)].slice(0, 6)) {
    out.push({
      class: 'MISSING_CONTROL',

      severity: 'LOW',
      title: `${fw} rail needs a "${task}" prompt no file here defines`,
      detail: `A flow that requires the ${task} prompt template is enabled, but no prompts entry in this configuration directory defines it. NeMo refuses to load such a config; an application that catches that error and carries on serves the model with no rails at all.`,
      remediationText: `Add a prompts entry with task: ${task}, or remove the flow that needs it.`,
      remediationTier: 2,
      evidence: { task, path: a.path, ...locate(task.split(' ')[0].replace(/_/g, ' '), a.content) },
    });
  }
  return out;
}

function plumbingFindings(a                  , fw        , m                )                    {
  const out                    = [];
  for (const e of m.endpoints.filter((x) => isCleartextRemote(x.url)).slice(0, 4)) {
    out.push({
      class: 'INSECURE_CONFIG',
      severity: 'MEDIUM',
      title: `${fw} "${a.name}" sends text to its checker over plain HTTP`,
      detail: `${e.anchor} is ${e.url}. Every prompt the guardrail screens crosses the network in the clear, and whoever sits on that path can also answer "allowed" for the checker.`,
      remediationText: 'Use HTTPS (or a local socket) for guardrail and action endpoints, and authenticate the endpoint the verdict comes from.',
      remediationTier: 2,
      evidence: { url: e.url, path: a.path, ...locate(e.anchor, a.content) },
    });
  }
  for (const r of m.nonStoppingRefusals.slice(0, 6)) {
    out.push({
      class: 'MISSING_CONTROL',
      severity: 'MEDIUM',
      title: `Colang flow "${r.flow}" refuses but does not stop`,
      detail: 'The refusal branch has no `stop` (or `abort`) after the bot message, so the flow ends and processing carries on: the user sees the refusal AND the model still generates the answer the check objected to.',
      remediationText: 'Follow every refusal inside a guardrail flow with `stop` (Colang 1.0) or `abort` (Colang 2.x).',
      remediationTier: 1,
      evidence: { flow: r.flow, path: a.path, ...locate(r.anchor, a.content) },
    });
  }
  if (m.unauthenticatedService) {
    out.push({
      class: 'WEAK_AUTH',
      severity: 'MEDIUM',
      title: `${fw} API "${a.name}" has no auth block`,
      detail: 'Without `auth`, the scanner API answers anyone who can reach it: it can be used to probe which payloads pass, and flooded until the application calling it times out (and, if it fails open, stops screening).',
      remediationText: 'Configure `auth` (http_bearer) and keep the service off public networks.',
      remediationTier: 2,
      evidence: { path: a.path, ...locate('app', a.content) },
    });
  }
  const screensInput = m.controls.some((c) => c.direction === 'input' || c.direction === 'both' || c.direction === 'unknown');

  const namesAreMeaningful = m.framework === 'nemo' || m.framework === 'bedrock' || m.framework === 'azure-rai' || m.framework === 'llm-guard' || m.framework === 'litellm';
  if (namesAreMeaningful && screensInput && m.controls.length && !m.controls.some((c) => c.injection)) {
    out.push({
      class: 'MISSING_CONTROL',
      severity: 'LOW',
      title: `${fw} "${a.name}" screens input but nothing in it targets prompt injection`,
      detail: `The configured controls (${m.controls.slice(0, 6).map((c) => c.name).join(', ')}) cover content categories, not instructions smuggled into the input. A jailbreak or injected instruction that is not itself offensive content passes all of them.`,
      remediationText: 'Add a prompt-attack / jailbreak control on the input side, or record which other layer is responsible for it.',
      remediationTier: 3,
      evidence: { controls: m.controls.slice(0, 20).map((c) => c.name), path: a.path },
    });
  }
  return out;
}

export function guardrailConfigFindings(a                  )                    {
  const text = a.content ?? '';
  const fw = ((a.meta?.framework                                  ) && FRAMEWORK_LABEL[a.meta .framework                      ] ? a.meta .framework : guardrailFramework(a.path, text))                             ;

  const out                    = textFindings(a, text, 'PROMPT_INJECTION').filter((f) => f.class === 'SECRET_EXPOSURE');
  if (!fw) return out;
  const m = guardrailModel(a.path, text, fw, Array.isArray(a.meta?.siblingPromptTasks) ? a.meta .siblingPromptTasks : []);
  if (!m) return out;
  const label = FRAMEWORK_LABEL[fw];
  const bad = m.controls.filter((c) => c.state !== 'enforcing');
  for (const c of bad.slice(0, MAX_CONTROL_FINDINGS)) out.push(controlFinding(a, label, c));
  out.push(...coverageFindings(a, label, m), ...judgeFindings(a, label, m), ...plumbingFindings(a, label, m));
  if (fw === 'nemo') out.push(...nemoInstructionFindings(a, text));
  return out;
}

function nemoInstructionFindings(a                  , text        )                    {
  const block = /^instructions\s*:[\s\S]*?(?=^\S)/m.exec(text + '\n~')?.[0];
  if (!block) return [];
  return textFindings(a, block, 'PROMPT_INJECTION').filter((f) => f.class === 'PROMPT_INJECTION').map((f) => ({
    ...f,
    title: `Injected directive in the guarded model's instructions ("${a.name}")`,
    detail: `${f.detail} NeMo sends \`instructions\` as the system prompt of the model the rails protect, so this text outranks what the rails were configured to allow.`,
  }));
}

