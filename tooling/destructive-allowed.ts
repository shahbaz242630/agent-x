// S185: every destructive line the repository's code holds, each with the guard
// that keeps it off the wrong thing and the test proving that guard. The rule and
// the shapes are in tooling/destructive-scan.ts; the check is
// tooling/checks/destructive-commands.test.ts.
//
// **Adding one.** A new delete, drop, purge or forced removal fails CI until it is
// named here. Name it by a piece of its line's text, give the identifier in its file
// that refuses the wrong target (a name rule, a tenant, a retention floor, a person's
// y/N), and the title of a test proving that refusal. An entry naming nothing, a
// guard no longer in its file or a proof title no longer in its test fails too, so
// the list can only shrink with the code.
import type { Allowed, NotACommand } from './destructive-scan.ts';

/** Its own proofs: tooling/checks/destructive-commands.test.ts. */
const CHECK = 'tooling/checks/destructive-commands.test.ts';
const TEMP_FOLDER_PROOF = {
  file: CHECK,
  title: 'removes recursively only a folder mkdtempSync made in the same file',
};
const LOAD_RUN_PROOF = { file: CHECK, title: "removes only the load run's own compose project and output folder" };

export const ALLOWED: readonly Allowed[] = [
  // --- Azure ---------------------------------------------------------------------------------------------------------
  {
    file: 'deploy/azure/stage-g-azure.ts',
    match: "server('delete', '--name', name, '--yes')",
    guard: 'refuseUnlessThrowaway(name);',
    proof: {
      file: 'deploy/azure/stage-g-azure.test.ts',
      title: 'refuses to delete the server %j, sending Azure no delete',
    },
    why: "Stage G's throwaway copy, removed after its test; staging's own server and the drill's can never fit its name",
  },
  {
    file: 'deploy/azure/stage-g-azure.ts',
    match: "'--method', 'delete', '--url', containerUrl",
    guard: 'THROWAWAY_ANCHORS_CONTAINER.test(container)',
    proof: {
      file: 'deploy/azure/stage-g-azure.test.ts',
      title: 'refuses to delete the anchors container %j, sending Azure no delete',
    },
    why: "a copy's own anchors container once its files' lock is up; staging's audit-anchors never fits",
  },
  {
    file: 'deploy/azure/deploy.ts',
    match: 'az resource delete --ids ${alert.id}',
    guard: "steps.terminal.ask('Delete them now so this run recreates them? [y/N] ')",
    proof: {
      file: 'deploy/azure/deploy.test.ts',
      title: 'stops on %j with nothing deleted or deployed, and prints the commands to delete them by hand',
    },
    why: 'printed for a person who answered no: the alerts a deployment must re-create in another workspace (S172)',
  },
  {
    file: 'deploy/azure/deploy.ts',
    match: "['resource', 'delete', '--ids', alert.id]",
    guard: "steps.terminal.ask('Delete them now so this run recreates them? [y/N] ')",
    proof: {
      file: 'deploy/azure/deploy.test.ts',
      title: 'says which alerts move and why, and on a y deletes them by their IDs before the deployment',
    },
    why: 'log alerts moving workspace, deleted only on a y, and re-created by the same run (S172)',
  },
  {
    file: 'deploy/azure/deploy.ts',
    match: "['rest', '--method', 'delete', '--url', url]",
    guard: 'containerApps/${JOBS_APP}?api-version',
    proof: {
      file: 'deploy/azure/deploy.test.ts',
      title: 'removes the jobs app a load run left once a plain apps has put the API back, and keeps it in a load run',
    },
    why: 'the jobs app a load run left, by its fixed name, only after a plain apps put the API back (4D2e D13)',
  },
  {
    file: 'deploy/azure/load.ts',
    match: "'--method', 'delete', '--url', loadJobUrl(subscription, job)",
    guard: 'has runs still going',
    proof: {
      file: 'deploy/azure/load.test.ts',
      title: "removes Stage G's jobs too where its run left them (4D2e), never while a run of one goes",
    },
    why: "the load test's own jobs, by their fixed names, never while a run of one goes",
  },
  // --- GitHub --------------------------------------------------------------------------------------------------------
  {
    file: 'deploy/image/prune.ts',
    match: "method: 'DELETE'",
    guard: 'imagesToKeep(versions, own, history)',
    proof: {
      file: 'deploy/image/prune.test.ts',
      title: 'keeps the newest five, and nothing older than the fifth is safe from removal',
    },
    why: 'old image versions in our own package, never the newest five, this run’s or a later one',
  },
  // --- Local folders, containers and the e2e stack ------------------------------------------------------------------
  ...(
    [
      ['deploy/azure/held-request.ts', 'rmSync(folder, { recursive'],
      ['deploy/azure/snapshot.ts', 'rmSync(dir, { recursive'],
      ['packages/testing/src/keys.ts', 'rmSync(directory, { recursive'],
      ['tooling/git-hooks/gitleaks.ts', 'rmSync(work, { recursive'],
      ['tooling/load/job.ts', 'rmSync(dir, { recursive'],
    ] as const
  ).map(([file, match]) => ({
    file,
    match,
    guard: 'mkdtempSync(',
    proof: TEMP_FOLDER_PROOF,
    why: 'a temporary folder this same function made, removed when it is done',
  })),
  ...['Dockerfile', 'tooling/load/Dockerfile'].map((file) => ({
    file,
    match: 'rm -rf /var/lib/apt/lists/* /usr/local/lib/node_modules/npm',
    guard:
      'rm -rf /var/lib/apt/lists/* /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack /opt/yarn-*',
    proof: { file: CHECK, title: 'removes in an image build only absolute paths written out' },
    why: "an image build's own package caches and unused tools, by absolute paths written out, inside the build",
  })),
  {
    file: 'packages/platform/src/storage/block-store.ts',
    match: 'rm(blocksOf(name), { recursive',
    guard: 'checkedBlobName(name)',
    proof: {
      file: 'packages/platform/src/storage/block-store.test.ts',
      title: 'refuses a name past plain path segments, a block out of range, and a part of no bytes, calling nothing',
    },
    why: "a committed file's own blocks folder; the name is plain path segments, so it can't climb out of the store",
  },
  {
    file: 'tooling/load/run.ts',
    match: "[...COMPOSE, 'down', '-v', '--remove-orphans']",
    guard: 'LOAD_PROJECT',
    proof: LOAD_RUN_PROOF,
    why: "the laptop load run's own compose project (-p agentx-load), its volumes with it",
    lines: 2,
  },
  {
    file: 'tooling/load/run.ts',
    match: 'rmSync(OUT_DIR, { recursive',
    guard: 'OUT_DIR',
    proof: LOAD_RUN_PROOF,
    why: "the load run's own output folder, tooling/load/.out",
  },
  {
    file: '.github/workflows/ci.yml',
    match: 'tooling/e2e/compose.e2e.yaml down --volumes',
    guard: 'tooling/e2e/compose.e2e.yaml',
    proof: { file: CHECK, title: "removes volumes in CI only of the end-to-end stack on CI's own runner" },
    why: "the end-to-end stack's volumes on a CI runner thrown away after the job",
  },
  {
    file: 'tooling/test-db/docker.ts',
    match: "'--volumes', ...expired",
    guard: 'label=${LABEL}',
    proof: {
      file: 'tooling/test-db/docker.test.ts',
      title: 'picks the containers whose expiry has passed, or has no readable expiry',
    },
    why: 'test Postgres containers past their expiry, found by our own label alone',
  },
  {
    file: 'tooling/test-db/docker.ts',
    match: "'--volumes', id]",
    guard: 'startPostgres',
    proof: { file: CHECK, title: "stops only the test server's own container" },
    why: 'the test Postgres container this same function started',
  },
  // --- The database: repairs, retention sweeps and rows used once ---------------------------------------------------
  {
    file: 'packages/core/src/modules/audit/infrastructure/chain-repair.ts',
    match: 'delete from audit.operator_signatures s where s.org_id = ${org}',
    guard: 'assertTenant(tx, org)',
    proof: {
      file: 'apps/operator/src/chain-restore.db.test.ts',
      title: 'rows that land otherwise than planned fail the check: everything rolled back',
    },
    why: "a chain repair's places emptied before the originals go back, one organisation, checked whole before commit",
  },
  {
    file: 'packages/core/src/modules/audit/infrastructure/chain-repair.ts',
    match: 'delete from audit.events e where e.org_id = ${org}',
    guard: 'assertTenant(tx, org)',
    proof: {
      file: 'apps/operator/src/chain-restore.db.test.ts',
      title: 'rows that land otherwise than planned fail the check: everything rolled back',
    },
    why: "a chain repair's planted rows removed, one organisation, checked whole before commit (PL-29)",
  },
  {
    file: 'packages/core/src/modules/audit/infrastructure/state-repair.ts',
    match: 'delete from ${table} as t where t.org_id = ${org} and t.id = ${id}',
    guard: 'numAffectedRows !== 1n',
    proof: {
      file: 'apps/operator/src/state-restore.db.test.ts',
      title: 'removes a planted row nothing signed ever made, keeping it whole in the plan',
    },
    why: 'a state repair removing one planted row by its key, one organisation, exactly one row or it fails',
  },
  {
    file: 'packages/core/src/modules/audit/infrastructure/holds-waiting.ts',
    match: ".deleteFrom('directory.holds_waiting')",
    guard: ".where('object_id', '=', objectId)",
    proof: {
      file: 'packages/core/src/modules/audit/infrastructure/holds-waiting.db.test.ts',
      title: 'only a row naming both the type and the ID of what the hold names goes with it',
    },
    why: "a hold's waiting row, by its organisation, type and ID, in the hold's own transaction",
  },
  {
    file: 'packages/core/src/modules/directory/infrastructure/org-work.ts',
    match: ".deleteFrom('directory.org_work')",
    guard: 'isThisMark',
    proof: {
      file: 'packages/core/src/modules/directory/infrastructure/org-work.db.test.ts',
      title: 'settling only touches its own job and its own organisation, to take it away or to move it',
    },
    why: 'a settled mark, only while it still reads as the one read',
  },
  {
    file: 'packages/core/src/modules/directory/infrastructure/org-work.ts',
    match: 'delete from directory.org_work w using held h',
    guard: 'w.org_id = h.org_id',
    proof: {
      file: 'packages/core/src/modules/directory/infrastructure/org-work.db.test.ts',
      title: 'each goes with nothing due, or moves to its next; only its own job, and only while it reads as listed',
    },
    why: 'a page of settled marks, each its own job and organisation, only while it reads as listed',
  },
  {
    file: 'packages/core/src/modules/identity/infrastructure/login-flows.ts',
    match: ".deleteFrom('identity.login_flows')",
    guard: ".where('ends_at', '<=', now)",
    proof: {
      file: 'packages/core/src/modules/identity/infrastructure/login-flows.db.test.ts',
      title: 'sweeps flows past their ten minutes, a batch at a time, and leaves the rest',
    },
    why: 'a sign-in flow taken once by its cookie hash, and the sweep of those past their ten minutes',
    lines: 2,
  },
  {
    file: 'packages/core/src/modules/identity/infrastructure/sessions.ts',
    match: "deleteFrom('identity.sessions').where('user_id', '=', userId)",
    guard: 'lockSessionsOf',
    proof: {
      file: 'packages/core/src/modules/identity/infrastructure/membership-changes.db.test.ts',
      title:
        'changes the role once the admin has signed in again, ending every session the member has in the same change',
    },
    why: "one person's sessions ended by a role change or deactivation (ADR-003 §7)",
  },
  {
    file: 'packages/core/src/modules/identity/infrastructure/sessions.ts',
    match: ".deleteFrom('identity.sessions')",
    guard: 'LONGEST_IDLE_SECONDS',
    proof: {
      file: 'packages/core/src/modules/identity/infrastructure/sessions.db.test.ts',
      title: 'deletes only sessions no setting could make live again: past their end, or unused past the longest idle',
    },
    why: 'sign-out by cookie hash, the sweep of sessions no setting could make live again, and the line above',
    lines: 3,
  },
  {
    file: 'packages/core/src/modules/identity/infrastructure/step-up-challenges.ts',
    match: ".deleteFrom('identity.step_up_challenges')",
    guard: ".where('ends_at', '<=', now)",
    proof: {
      file: 'packages/core/src/modules/identity/infrastructure/step-up-challenges.db.test.ts',
      title: 'sweeps challenges out of time, a batch at a time, and leaves the rest',
    },
    why: 'a verified challenge consumed once for its own session, and the sweep of those out of time',
    lines: 2,
  },
  {
    file: 'packages/core/src/modules/notifications/infrastructure/outbox.ts',
    match: "tx.deleteFrom('notifications.outbox')",
    guard: 'OUTBOX_RETENTION_DAYS',
    proof: {
      file: 'packages/core/src/modules/notifications/infrastructure/outbox.db.test.ts',
      title: 'sweeps notices done and past the retention, oldest first, and never one still to send',
    },
    why: 'notices sent or given up, past their 30 days',
  },
  ...['provider_events.inbox', 'security.partner_event_evidence'].map((table) => ({
    file: 'packages/core/src/modules/provider-events/infrastructure/provider-events.ts',
    match: `.deleteFrom('${table}')`,
    guard: 'retentionDays < LEAST_RETENTION_DAYS',
    proof: {
      file: 'packages/core/src/modules/provider-events/infrastructure/provider-events.test.ts',
      title: 'keeps messages at least',
    },
    why: "partner messages past the security events' retention, never under 30 days (S185)",
  })),
  {
    file: 'packages/core/src/modules/security-events/infrastructure/security-events.ts',
    match: "tx.deleteFrom('security.events')",
    guard: 'retentionDays < LEAST_RETENTION_DAYS',
    proof: {
      file: 'packages/core/src/modules/security-events/infrastructure/security-events.db.test.ts',
      title: 'keeps events at least',
    },
    why: 'security events past their retention, never under 30 days',
  },
  {
    file: 'packages/platform/src/db/idempotency.ts',
    match: 'delete from idempotency.keys',
    guard: 'IDEMPOTENCY_RETENTION_DAYS',
    proof: {
      file: 'packages/platform/src/db/idempotency.db.test.ts',
      title: 'deletes only the keys past their 30 days, of this organisation alone, and says how many',
    },
    why: "one organisation's idempotency keys past their 30 days, which the database's own policy holds too",
  },
  // --- Test helpers: a throwaway test database only -----------------------------------------------------------------
  {
    file: 'packages/testing/src/db/owner-tamper.ts',
    match: 'delete from ${table} where org_id = $1 and id = $2',
    guard: 'database: TestDatabase',
    proof: { file: 'packages/testing/src/db/owner-tamper.db.test.ts', title: 'deletes the row' },
    why: "FX-TAMPER's planted delete, on a throwaway test database",
  },
  {
    file: 'packages/testing/src/db/owner-tamper.ts',
    match: 'delete from audit.events where org_id = $1 and subject_type = $2 and subject_id = $3',
    guard: 'database: TestDatabase',
    proof: { file: 'packages/testing/src/db/owner-tamper.db.test.ts', title: "deletes the row's events, and no other" },
    why: "FX-TAMPER's planted delete of a row's events, on a throwaway test database",
  },
  {
    file: 'packages/testing/src/db/owner-tamper.ts',
    match: 'delete from audit.events where org_id = $1 and seq > $2::bigint',
    guard: 'database: TestDatabase',
    proof: {
      file: 'packages/testing/src/db/owner-tamper.db.test.ts',
      title: 'winds the chain back: every event past a saved head deleted, and the head put back',
    },
    why: "FX-TAMPER's planted wind-back, on a throwaway test database",
  },
  {
    file: 'packages/testing/src/db/test-database.ts',
    match: 'DROP DATABASE IF EXISTS ${quoted} WITH (FORCE)',
    guard: 'const name = `t_${randomUUID()',
    proof: {
      file: 'packages/testing/src/db/test-database.db.test.ts',
      title: 'deletes the database on drop, even with a session still open',
    },
    why: "a test's own database, named t_<uuid> by the same function, on the test server",
  },
];

/** Lines the shapes catch that run nothing destructive. */
export const NOT_COMMANDS: readonly NotACommand[] = [
  {
    file: 'apps/api/src/contract.ts',
    match: 'const OPENAPI_METHODS',
    why: "OpenAPI's method names, read from the spec",
  },
  {
    file: 'deploy/azure/policy.ts',
    match: "'baseBlob', 'delete', 'daysAfterCreationGreaterThan'",
    why: "reads a lifecycle rule's delete age to check it, deleting nothing",
  },
  {
    file: 'deploy/azure/stage-g.ts',
    match: "return { command: 'delete', name: named }",
    why: "the runner's own command word, whose remove() and adapter hold the name rule",
  },
  {
    file: 'deploy/compose/prepare.ts',
    match: 'down --volumes), delete the file, and run prepare again',
    why: 'words to a person about their own laptop stack',
  },
  { file: 'tooling/load/run.ts', match: 'The stack is left up (--keep)', why: 'words to a person, after --keep' },
  {
    file: 'packages/platform/src/db/schema-guard.ts',
    match: 'const TABLE_RIGHTS',
    why: 'the privilege names the schema guard reads, granting nothing',
  },
];
