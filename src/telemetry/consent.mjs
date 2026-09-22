const TRUTHY = new Set(['1', 'true', 'yes', 'on']);
const FALSY = new Set(['0', 'false', 'no', 'off']);

export const LEVELS = ['off', 'basic', 'samples'];

export const PROCESS_START = Math.floor(globalThis.performance?.timeOrigin ?? Date.now());

const CI_MARKERS = ['GITHUB_ACTIONS', 'GITLAB_CI', 'CIRCLECI', 'BUILDKITE', 'JENKINS_URL', 'TF_BUILD', 'BITBUCKET_BUILD_NUMBER', 'TEAMCITY_VERSION', 'CODEBUILD_BUILD_ID', 'DRONE', 'TRAVIS', 'APPVEYOR', 'SEMAPHORE'];

const norm = (v) => String(v ?? '').trim().toLowerCase();

export function isCi(env = process.env) {
  return TRUTHY.has(norm(env.CI)) || CI_MARKERS.some((k) => String(env[k] ?? '').trim() !== '');
}

const off = (reason) => ({ enabled: false, level: 'off', reason });

const on = (level, reason) => ({ enabled: true, level, reason });

export function telemetryState({ env = process.env, cfg = {}, enrolled = false, processStart = PROCESS_START } = {}) {
  const dnt = norm(env.DO_NOT_TRACK);
  if (dnt && !FALSY.has(dnt)) return off('DO_NOT_TRACK is set');
  const forced = norm(env.SHOMRA_TELEMETRY);
  if (FALSY.has(forced)) return off('SHOMRA_TELEMETRY=0');
  if (enrolled) return off('this machine is enrolled - its org decides what is shared, and this channel never carries enrolled traffic');
  const saved = cfg?.telemetry ?? {};
  if (saved.level === 'off') return off('turned off with `shomra telemetry off`');
  const level = forced === 'samples' || saved.level === 'samples' ? 'samples' : 'basic';
  if (TRUTHY.has(forced) || forced === 'samples' || forced === 'basic') return on(level, 'SHOMRA_TELEMETRY');
  if (saved.level === 'basic' || saved.level === 'samples') return on(level, 'turned on with `shomra telemetry on`');
  if (isCi(env)) return off('CI - nobody here has seen the notice; set SHOMRA_TELEMETRY=1 to share');
  const noticeAt = Date.parse(saved.noticeAt ?? '');
  if (!Number.isFinite(noticeAt) || noticeAt >= processStart) {
    return { enabled: false, level: 'basic', reason: 'the notice has not been shown yet - nothing is collected until it has', pending: true };
  }
  return on('basic', `default - notice shown ${new Date(noticeAt).toISOString().slice(0, 10)}`);
}
