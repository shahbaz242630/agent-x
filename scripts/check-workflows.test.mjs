import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { checkWorkflow, checkoutStepsKeepingCredentials, collectJobs, main, runCheck } from './check-workflows.mjs';

const SHA = '3d3c42e5aac5ba805825da76410c181273ba90b1';

const GOOD = `name: CI
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  verify:
    name: Verify
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@${SHA} # v7.0.1
        with:
          persist-credentials: false
      - name: Setup
        uses: actions/setup-node@${SHA} # v7.0.0
      - run: echo ok
        env:
          GITHUB_TOKEN: \${{ secrets.GITHUB_TOKEN }}
`;

const rules = (contents) => checkWorkflow('wf.yml', contents).map((violation) => violation.rule);

test('a compliant workflow has no violations', () => {
  assert.deepEqual(checkWorkflow('wf.yml', GOOD), []);
});

test('permissions: {} is accepted as minimal', () => {
  assert.deepEqual(rules(GOOD.replace('permissions:\n  contents: read', 'permissions: {}')), []);
});

test('an action pinned to a tag is rejected', () => {
  assert.deepEqual(rules(GOOD.replace(`actions/setup-node@${SHA}`, 'actions/setup-node@v7')), ['pinned-actions']);
});

test('an action without any ref is rejected', () => {
  assert.deepEqual(rules(GOOD.replace(`actions/setup-node@${SHA} # v7.0.0`, 'actions/setup-node')), ['pinned-actions']);
});

test('an action outside the allowlist is rejected even when pinned', () => {
  assert.deepEqual(rules(GOOD.replace('actions/setup-node', 'someone/untrusted-action')), ['allowed-actions']);
});

test('a local composite action is allowed', () => {
  assert.deepEqual(rules(GOOD.replace(`actions/setup-node@${SHA} # v7.0.0`, './.github/actions/setup')), []);
});

test('pull_request_target is rejected', () => {
  assert.ok(rules(GOOD.replace('  pull_request:', '  pull_request_target:')).includes('no-pull-request-target'));
});

test('write-all is rejected', () => {
  const found = rules(GOOD.replace('permissions:\n  contents: read', 'permissions: write-all'));
  assert.ok(found.includes('no-write-all'));
  assert.ok(found.includes('minimal-permissions'));
});

test('a missing top-level permissions block is rejected', () => {
  assert.deepEqual(rules(GOOD.replace('permissions:\n  contents: read\n', '')), ['minimal-permissions']);
});

test('a top-level permissions block without contents: read is rejected', () => {
  assert.deepEqual(rules(GOOD.replace('contents: read', 'contents: write')), ['minimal-permissions']);
});

test('a repository secret in a pull_request workflow is rejected', () => {
  assert.deepEqual(rules(GOOD.replace('secrets.GITHUB_TOKEN', 'secrets.PARTNER_API_KEY')), ['no-secrets-on-pull-request']);
});

test('a repository secret is allowed when the workflow does not run on pull_request', () => {
  const pushOnly = GOOD.replace('  pull_request:\n', '').replace('secrets.GITHUB_TOKEN', 'secrets.PARTNER_API_KEY');
  assert.deepEqual(rules(pushOnly), []);
});

test('a job without timeout-minutes is rejected', () => {
  assert.deepEqual(rules(GOOD.replace('    timeout-minutes: 10\n', '')), ['job-timeout']);
});

test('checkout without persist-credentials: false is rejected', () => {
  const found = checkWorkflow('wf.yml', GOOD.replace('        with:\n          persist-credentials: false\n', ''));
  assert.deepEqual(found.map((violation) => violation.rule), ['checkout-credentials']);
  assert.match(found[0].message, /line 14/);
});

test('checkout with persist-credentials: true is rejected', () => {
  assert.deepEqual(rules(GOOD.replace('persist-credentials: false', 'persist-credentials: true')), ['checkout-credentials']);
});

test('checkout under a named step is checked', () => {
  const named = `steps:
      - name: Checkout
        uses: actions/checkout@${SHA}
        with:
          persist-credentials: false
      - name: Checkout again
        uses: actions/checkout@${SHA}
      - run: echo done
`;
  assert.deepEqual(checkoutStepsKeepingCredentials(named), [7]);
});

test('persist-credentials on a later step does not cover an earlier checkout', () => {
  const tricky = `steps:
      - uses: actions/checkout@${SHA}
      - uses: actions/checkout@${SHA}
        with:
          persist-credentials: false
`;
  assert.deepEqual(checkoutStepsKeepingCredentials(tricky), [2]);
});

test('collectJobs stops at the next top-level key and handles no jobs', () => {
  assert.deepEqual(collectJobs('name: x\non: push\n'), []);
  const jobs = collectJobs('jobs:\n  a:\n    timeout-minutes: 1\n  b:\n    runs-on: x\nenv:\n  c: 1\n');
  assert.deepEqual(jobs.map((job) => job.name), ['a', 'b']);
});

function withWorkflows(files, run) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wf-policy-'));
  try {
    const workflowDir = path.join(dir, '.github', 'workflows');
    fs.mkdirSync(workflowDir, { recursive: true });
    for (const [name, contents] of Object.entries(files)) fs.writeFileSync(path.join(workflowDir, name), contents);
    return run(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('runCheck scans only yml/yaml files and passes a compliant set', () => {
  withWorkflows({ 'ci.yml': GOOD, 'other.yaml': GOOD, 'notes.txt': 'uses: bad/action@main' }, (cwd) => {
    const result = runCheck({ cwd });
    assert.equal(result.ok, true);
    assert.equal(result.files.length, 2);
  });
});

test('runCheck reports violations with the workflow path', () => {
  withWorkflows({ 'bad.yml': GOOD.replace(`actions/setup-node@${SHA}`, 'actions/setup-node@main') }, (cwd) => {
    const result = runCheck({ cwd });
    assert.equal(result.ok, false);
    assert.equal(result.violations[0].path, '.github/workflows/bad.yml');
  });
});

test('runCheck passes when there is no workflow directory', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wf-policy-empty-'));
  try {
    assert.deepEqual(runCheck({ cwd: dir }), { ok: true, violations: [], files: [] });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('main returns 0 and logs success for a compliant repo', () => {
  withWorkflows({ 'ci.yml': GOOD }, (cwd) => {
    const logged = [];
    assert.equal(main({ cwd, log: (line) => logged.push(line), error: () => {} }), 0);
    assert.match(logged[0], /passed \(1 workflow file/);
  });
});

test('main returns 1 and lists every violation', () => {
  withWorkflows({ 'ci.yml': GOOD.replace('    timeout-minutes: 10\n', '') }, (cwd) => {
    const errors = [];
    assert.equal(main({ cwd, log: () => {}, error: (line) => errors.push(line) }), 1);
    assert.match(errors.join('\n'), /\[job-timeout\] \.github\/workflows\/ci\.yml/);
  });
});
