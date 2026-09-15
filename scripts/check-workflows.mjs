#!/usr/bin/env node
// Workflow hygiene gate for .github/workflows/*.yml, run by the CI
// "Workflow policy" job. A workflow fails this check when it:
//   - mentions `pull_request_target` anywhere outside a comment
//   - mentions `write-all` anywhere outside a comment
//   - has a top-level `permissions:` that is missing, grants any write scope,
//     or lacks `contents: read` (`permissions: {}` is allowed); writes belong
//     on individual jobs
//   - uses an action that is not pinned to a full 40-character commit SHA
//   - uses an action outside ALLOWED_ACTIONS (extend the list deliberately)
//   - runs on `pull_request` and references any secret other than GITHUB_TOKEN
//   - has a job without `timeout-minutes`
//   - checks out code without `persist-credentials: false`
//   - quotes a mapping key (the checks are line-based, so quoted keys such as
//     `"uses":` could hide a step from them; this fails closed instead)
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const ALLOWED_ACTIONS = new Set([
  'actions/checkout',
  'actions/setup-node',
  'actions/dependency-review-action',
  'github/codeql-action/init',
  'github/codeql-action/analyze',
  'gitleaks/gitleaks-action',
  'zizmorcore/zizmor-action',
  // SEC-SC-02: the software bill of materials of the image the End to end job builds.
  'anchore/sbom-action',
]);

const SHA_PATTERN = /^[0-9a-f]{40}$/i;
const STEP_START = /^\s*-\s/;

export function checkWorkflow(relativePath, contents) {
  const violations = [];
  const add = (rule, message) => violations.push({ rule, message, path: relativePath });
  const code = stripComments(contents);

  if (/^\s*-?\s*["'][A-Za-z0-9_-]+["']\s*:/m.test(code)) {
    add('unquoted-keys', 'Mapping keys must not be quoted; the policy checks rely on unquoted keys.');
  }

  if (/\bpull_request_target\b/.test(code)) {
    add('no-pull-request-target', 'pull_request_target exposes trusted context to untrusted PR code.');
  }

  if (/\bwrite-all\b/.test(code)) {
    add('no-write-all', 'write-all is never acceptable.');
  }

  if (!hasMinimalTopLevelPermissions(code)) {
    add(
      'minimal-permissions',
      'Top-level `permissions:` must grant only read scopes, including `contents: read` (or be `{}`); grant writes per job.',
    );
  }

  for (const match of contents.matchAll(/^\s*-?\s*uses\s*:\s*['"]?([^\s'"#]+)['"]?/gm)) {
    const ref = match[1];
    if (ref.startsWith('./')) continue; // local composite action
    const at = ref.lastIndexOf('@');
    const name = at >= 0 ? ref.slice(0, at) : ref;
    const version = at >= 0 ? ref.slice(at + 1) : '';

    if (!SHA_PATTERN.test(version)) {
      add('pinned-actions', `${ref} must be pinned to a full 40-character commit SHA (with a "# vX" comment).`);
    }
    if (!ALLOWED_ACTIONS.has(name)) {
      add('allowed-actions', `${name} is not in the reviewed action allowlist.`);
    }
  }

  if (/\bpull_request\b/.test(code)) {
    for (const match of contents.matchAll(/\$\{\{\s*secrets\.([A-Za-z0-9_]+)/g)) {
      if (match[1] === 'GITHUB_TOKEN') continue;
      add('no-secrets-on-pull-request', `secrets.${match[1]} is referenced in a workflow that runs on pull_request.`);
    }
  }

  for (const job of collectJobs(contents)) {
    if (!/^\s+timeout-minutes\s*:\s*\d+/m.test(job.block)) {
      add('job-timeout', `Job "${job.name}" has no timeout-minutes.`);
    }
  }

  for (const line of checkoutStepsKeepingCredentials(contents)) {
    add('checkout-credentials', `actions/checkout at line ${line} must set persist-credentials: false.`);
  }

  return violations;
}

// Removes YAML comments: a `#` at the start of a line or after whitespace.
export function stripComments(contents) {
  return contents
    .split(/\r?\n/)
    .map((line) => line.replace(/(^|\s)#.*$/, ''))
    .join('\n');
}

// Accepts block style or flow style (`{ contents: read }`, `{}`). Every entry
// must be `scope: read|none`, and `contents: read` must be present unless the
// map is empty. Anything unrecognised fails closed.
export function hasMinimalTopLevelPermissions(code) {
  const lines = code.split('\n');
  const start = lines.findIndex((line) => /^permissions\s*:/.test(line));
  if (start < 0) return false;

  let entries;
  const inline = lines[start].replace(/^permissions\s*:/, '').trim();
  if (inline === '') {
    entries = [];
    for (const line of lines.slice(start + 1)) {
      if (line.trim() !== '' && !/^[ \t]/.test(line)) break; // next top-level key
      entries.push(line);
    }
  } else {
    const flow = inline.match(/^\{([^}]*)\}$/);
    if (!flow) return false; // a scalar such as read-all
    entries = flow[1].split(',');
  }

  const scopes = entries.map((entry) => entry.trim()).filter(Boolean);
  if (scopes.length === 0) return inline !== ''; // `{}` is fine; a bare `permissions:` is not

  const parsed = scopes.map((entry) => entry.match(/^([a-z-]+)\s*:\s*(read|none)$/));
  if (parsed.some((scope) => scope === null)) return false;
  return parsed.some((scope) => scope[1] === 'contents' && scope[2] === 'read');
}

export function collectJobs(contents) {
  const jobsStart = contents.search(/^jobs\s*:\s*$/m);
  if (jobsStart < 0) return [];
  // The jobs section ends at the next column-0 key.
  const rest = contents.slice(jobsStart).split(/\r?\n/).slice(1);
  const lines = [];
  for (const line of rest) {
    if (/^\S/.test(line)) break;
    lines.push(line);
  }
  const jobs = [];
  for (const line of lines) {
    const header = line.match(/^ {2}([A-Za-z0-9_-]+)\s*:\s*$/);
    if (header) {
      jobs.push({ name: header[1], lines: [] });
    } else if (jobs.length > 0) {
      jobs[jobs.length - 1].lines.push(line);
    }
  }
  return jobs.map((job) => ({ name: job.name, block: job.lines.join('\n') }));
}

// Returns the 1-based line numbers of actions/checkout steps that do not set
// `persist-credentials: false`. Handles both `- uses: actions/checkout@…` and a
// `uses:` key further down a step that starts with `- name:`.
export function checkoutStepsKeepingCredentials(contents) {
  const lines = contents.split(/\r?\n/);
  const offending = [];
  lines.forEach((line, index) => {
    if (!/^\s*(-\s+)?uses\s*:\s*['"]?actions\/checkout@/.test(line)) return;

    let start = index;
    if (!STEP_START.test(line)) {
      const usesIndent = line.search(/\S/);
      start = index - 1;
      while (start >= 0 && !(STEP_START.test(lines[start]) && lines[start].search(/\S/) < usesIndent)) start--;
      if (start < 0) start = index;
    }

    const stepIndent = lines[start].search(/\S/);
    let end = index + 1;
    while (end < lines.length && (lines[end].trim() === '' || lines[end].search(/\S/) > stepIndent)) end++;

    const step = lines.slice(start, end).join('\n');
    if (!/^\s*persist-credentials\s*:\s*false\s*$/m.test(step)) offending.push(index + 1);
  });
  return offending;
}

export function runCheck({ cwd = process.cwd(), workflowDir = path.join('.github', 'workflows') } = {}) {
  const absoluteDir = path.join(cwd, workflowDir);
  if (!fs.existsSync(absoluteDir)) return { ok: true, violations: [], files: [] };

  const files = fs
    .readdirSync(absoluteDir, { withFileTypes: true })
    .filter((entry) => entry.isFile() && /\.ya?ml$/i.test(entry.name))
    .map((entry) => path.join(absoluteDir, entry.name))
    .sort();

  const violations = files.flatMap((file) =>
    checkWorkflow(path.relative(cwd, file).replace(/\\/g, '/'), fs.readFileSync(file, 'utf8')),
  );

  return { ok: violations.length === 0, violations, files: files.map((file) => path.relative(cwd, file)) };
}

export function main({ cwd = process.cwd(), log = console.log, error = console.error } = {}) {
  const result = runCheck({ cwd });
  if (result.ok) {
    log(`Workflow policy check passed (${result.files.length} workflow file(s)).`);
    return 0;
  }
  error('Workflow policy check failed:');
  for (const violation of result.violations) {
    error(`- [${violation.rule}] ${violation.path}: ${violation.message}`);
  }
  return 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exit(main());
}
