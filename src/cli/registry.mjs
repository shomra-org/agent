import { cmdAdd } from '../commands/add.mjs';
import { cmdAgentIdentity } from '../commands/agent-identity.mjs';
import { cmdBaseline, cmdCheck } from '../commands/check.mjs';
import { cmdCorpus } from '../commands/corpus.mjs';
import { cmdDesign } from '../commands/design.mjs';
import { cmdDoctor } from '../commands/doctor.mjs';
import { cmdFix } from '../commands/fix.mjs';
import { cmdGate } from '../commands/gate.mjs';
import { cmdInstallPrecommit } from '../commands/git-hooks.mjs';
import { cmdInit } from '../commands/init.mjs';
import { cmdInstallHook } from '../commands/install-hook.mjs';
import { cmdLedger } from '../commands/ledger.mjs';
import { cmdLlmProxy } from '../commands/llm-proxy.mjs';
import { cmdMcp, cmdMcpGuard } from '../commands/mcp.mjs';
import { cmdMemoryScan } from '../commands/memory-scan.mjs';
import { cmdModelScan } from '../commands/model-scan.mjs';
import { cmdModels } from '../commands/models.mjs';
import { cmdNew } from '../commands/new.mjs';
import { cmdPlan, cmdPlanGuard } from '../commands/plan.mjs';
import { cmdPr } from '../commands/pr.mjs';
import { cmdProtect } from '../commands/protect.mjs';
import { cmdProvenance } from '../commands/provenance.mjs';
import { cmdCampaign, cmdHarden, cmdRedteam } from '../commands/redteam.mjs';
import { cmdRules } from '../commands/rules.mjs';
import { cmdRun } from '../commands/run.mjs';
import { cmdScanZip } from '../commands/scan-zip.mjs';
import { cmdScan } from '../commands/scan.mjs';
import { cmdSecrets } from '../commands/secrets.mjs';
import { cmdStatus } from '../commands/status.mjs';
import { cmdWhy } from '../commands/why.mjs';
import { cmdPromptGuard } from '../guard/prompt-guard.mjs';
import { cmdSessionGuard } from '../guard/session-guard.mjs';
import { cmdResultGuard } from '../guard/result-guard.mjs';
import { cmdToolGuard } from '../guard/tool-guard.mjs';

export const COMMANDS = {
  init: (f) => cmdInit(f),
  scan: (f) => cmdScan(f),
  report: (f) => cmdScan({ ...f, report: true }),
  gate: (f, p) => cmdGate(f, p),
  run: (f, p) => cmdRun(f, p),
  check: (f, p) => cmdCheck(f, p),
  pr: (f, p) => cmdPr(f, p),
  baseline: (f, p) => cmdBaseline(f, p),
  fix: (f, p) => cmdFix(f, p),
  why: (f, p) => cmdWhy(f, p),
  provenance: (f, p) => cmdProvenance(f, p),
  'install-precommit': (f, p) => cmdInstallPrecommit(f, p),
  'scan-zip': (f, p) => cmdScanZip(f, p),
  'model-scan': (f, p) => cmdModelScan(f, p),
  models: (f, p) => cmdModels(f, p),
  'memory-scan': (f, p) => cmdMemoryScan(f, p),
  redteam: (f) => cmdRedteam(f),
  campaign: (f) => cmdCampaign(f),
  harden: (f) => cmdHarden(f),
  'agent-identity': (f, p) => cmdAgentIdentity(f, p),
  'agent-id': (f, p) => cmdAgentIdentity(f, p),
  'llm-proxy': (f) => cmdLlmProxy(f),
  'tool-guard': (f) => cmdToolGuard(f),
  'mcp-guard': (f, p) => cmdMcpGuard(f, p),
  'result-guard': (f) => cmdResultGuard(f),
  'prompt-guard': (f) => cmdPromptGuard(f),
  'plan-guard': (f) => cmdPlanGuard(f),
  'session-guard': (f) => cmdSessionGuard(f),
  plan: (f, p) => cmdPlan(f, p),
  corpus: (f, p) => cmdCorpus(f, p),
  rules: (f, p) => cmdRules(f, p),
  design: (f, p) => cmdDesign(f, p),
  add: (f, p) => cmdAdd(f, p),
  'install-hook': (f) => cmdInstallHook(f),
  protect: (f) => cmdProtect(f),
  ledger: (f) => cmdLedger(f),
  doctor: (f) => cmdDoctor(f),
  new: (f, p) => cmdNew(f, p),
  mcp: (f, p) => cmdMcp(f, p),
  secrets: (f, p) => cmdSecrets(f, p),
  status: () => cmdStatus(),
};

export const ADMIN_VERBS = new Set([
  'scan-zip', 'model-scan', 'memory-scan',
  'redteam', 'campaign', 'harden',
  'agent-identity', 'agent-id', 'llm-proxy',
]);
