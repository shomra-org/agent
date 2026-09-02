import { execSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

export const GATE_KINDS = ['mcp', 'skill', 'command', 'subagent', 'hook', 'rules', 'agent-card', 'memory', 'auto'];

/**
 * ⚠ A CLOUD AGENT SESSION IS NOT A DEVELOPER MACHINE, and until this existed it
 * reported as one. Claude Code on the web runs in an EPHEMERAL container: fresh
 * $HOME, no `shomra` config, a hostname nobody will ever see again. It carries
 * no CI variables, so it fell through to LOCAL - and an operator counting
 * "screened laptops" was counting containers that no longer exist.
 *
 * ⚠ CI IS CHECKED FIRST and stays first. A cloud session driven by a GitHub
 * Action is CI: that branch carries repo, ref and commit, which is the stronger
 * attribution. REMOTE is what is left when nothing else names where this ran.
 */
const REMOTE_MARKERS = ['CLAUDE_CODE_CONTAINER_ID', 'CLAUDE_CODE_ENVIRONMENT_RUNNER_VERSION'];

export function remoteRunner(e = process.env) {
  for (const key of REMOTE_MARKERS) if (String(e?.[key] ?? '').trim()) return 'claude-code-cloud';
  if (/^remote/i.test(String(e?.CLAUDE_CODE_ENTRYPOINT ?? '').trim())) return 'claude-code-cloud';
  return null;
}

export function detectEnv(env) {
  const e = env ?? process.env;
  const pick = (...keys) => {
    for (const k of keys) if (e[k]?.trim()) return e[k].trim();
    return undefined;
  };
  let ci = null;

  if (e.GITHUB_ACTIONS)
    ci = {
      ciProvider: 'github-actions',
      repo: e.GITHUB_REPOSITORY,

      repoUrl: e.GITHUB_SERVER_URL && e.GITHUB_REPOSITORY ? `${e.GITHUB_SERVER_URL.replace(/\/+$/, '')}/${e.GITHUB_REPOSITORY}` : undefined,
      ref: e.GITHUB_REF_NAME,
      commit: e.GITHUB_SHA,
    };
  else if (e.GITLAB_CI)
    ci = { ciProvider: 'gitlab-ci', repo: e.CI_PROJECT_PATH, repoUrl: e.CI_PROJECT_URL, ref: e.CI_COMMIT_REF_NAME, commit: e.CI_COMMIT_SHA };
  else if (e.CIRCLECI)
    ci = {
      ciProvider: 'circleci',
      repo: e.CIRCLE_PROJECT_REPONAME,
      repoUrl: e.CIRCLE_REPOSITORY_URL,
      ref: e.CIRCLE_BRANCH,
      commit: e.CIRCLE_SHA1,
    };
  else if (e.TF_BUILD)
    ci = {
      ciProvider: 'azure-pipelines',
      repo: e.BUILD_REPOSITORY_NAME,
      repoUrl: e.BUILD_REPOSITORY_URI,
      ref: e.BUILD_SOURCEBRANCHNAME,
      commit: e.BUILD_SOURCEVERSION,
    };
  else if (e.BITBUCKET_BUILD_NUMBER)
    ci = {
      ciProvider: 'bitbucket-pipelines',
      repo: e.BITBUCKET_REPO_FULL_NAME,
      repoUrl: e.BITBUCKET_GIT_HTTP_ORIGIN,
      ref: e.BITBUCKET_BRANCH,
      commit: e.BITBUCKET_COMMIT,
    };

  else if (e.JENKINS_URL) ci = { ciProvider: 'jenkins', repo: pick('JOB_NAME'), repoUrl: pick('GIT_URL'), ref: e.GIT_BRANCH, commit: e.GIT_COMMIT };
  else if (e.CI) ci = { ciProvider: 'ci', repo: undefined, repoUrl: undefined, ref: undefined, commit: undefined };

  if (ci) {

    const git = gitContext();
    return {
      environment: 'CI',
      ciProvider: ci.ciProvider,
      repo: ci.repo ?? git.repo,
      repoUrl: ci.repoUrl ?? git.repoUrl,
      ref: ci.ref ?? git.ref,
      commit: ci.commit ?? git.commit,
    };
  }

  const runner = remoteRunner(e);
  if (runner) return { environment: 'REMOTE', runner, ...gitContext() };

  return { environment: 'LOCAL', ...gitContext() };
}

function gitContext() {
  const run = (args) => {
    try {
      return execSync(`git ${args}`, { stdio: ['ignore', 'pipe', 'ignore'], timeout: 2000 })
        .toString()
        .trim();
    } catch {
      return undefined;
    }
  };
  const origin = run('config --get remote.origin.url');
  let repo;
  if (origin) {
    const m = origin.match(/[:/]([^/:]+\/[^/]+?)(?:\.git)?$/);
    repo = m ? m[1] : undefined;
  }

  let repoUrl = origin || undefined;
  if (repoUrl) repoUrl = repoUrl.replace(/^([a-z][\w+.-]*:\/\/)[^/@]*@/i, '$1');
  return { repo, repoUrl, ref: run('rev-parse --abbrev-ref HEAD'), commit: run('rev-parse HEAD') };
}

export function collectSiblings(fullTarget, relPath) {
  const MAX = 400;
  const MAX_DEPTH = 3;
  const SKIP = new Set(['.git', 'node_modules', '.venv', 'venv', '__pycache__', 'dist', 'build']);
  if (!fullTarget || !relPath) return [];
  try {
    const root = path.dirname(fullTarget);
    const rootRel = path.dirname(relPath);
    const out = [];
    const walk = (dir, depth) => {
      if (out.length >= MAX || depth > MAX_DEPTH) return;
      let entries;
      try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
      for (const e of entries) {
        if (out.length >= MAX) return;
        const full = path.join(dir, e.name);
        if (e.isDirectory()) {
          if (!SKIP.has(e.name)) walk(full, depth + 1);
          continue;
        }
        if (!e.isFile() || full === fullTarget) continue;
        const rel = path.relative(root, full).split(path.sep).join('/');
        out.push(rootRel && rootRel !== '.' ? `${rootRel}/${rel}` : rel);
      }
    };
    walk(root, 0);
    return out;
  } catch {
    return [];
  }
}
