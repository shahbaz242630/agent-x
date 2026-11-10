// The operator's command on its job (B1c-2b). Nothing here reaches Azure: the
// CLI is a stand-in holding the job and the API as Azure would, answering
// from them and recording each call. A PATCH is read from the file it is sent
// in, as it is sent, and taken only after a few readings, as Azure settles a
// change in the background; time moves only when the runner sleeps.
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, rmSync } from 'node:fs';
import path from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  activityExportRequest,
  auditExportRequest,
  createOrganizationRequest,
  handoffRequest,
  NO_REQUEST_PROBLEM,
  NO_STORE_PROBLEM,
  REQUEST_LIMIT_BYTES,
  chainRebaseRequest,
  chainRecoveryRequest,
  chainRestoreRequest,
  restoreCheckRequest,
  stateRecoveryRequest,
  stateRestoreRequest,
  UUID_V7,
} from '../../apps/operator/src/request.ts';
import type { Az, AzResult } from './deploy.ts';
import { jobName, JOBS_API, UsageError } from './jobs.ts';
import {
  auditExport,
  chainRebase,
  chainRestore,
  createOrganization,
  handoffChange,
  type HandoffArguments,
  inviteFirstAdmin,
  main,
  NO_REQUEST,
  OPERATOR_JOB,
  parseArguments,
  parseAuditExport,
  parseFirstAdmin,
  parseHandoff,
  parseRebase,
  parseRecoveryPlan,
  parseRestore,
  parseStatePlan,
  parseStateRestore,
  recoveryPlan,
  REQUEST_SECRET,
  RESTORE_JOB,
  RESTORE_REQUEST_SECRET,
  restoreCheck,
  stateRecoveryPlan,
  stateRestore,
  USAGE,
} from './operator.ts';
import { environmentSnapshot, inCopy } from './snapshot.ts';

/** A failure no real run chooses: the next removals of a folder refused, as Windows refuses a file a scanner holds. */
const faults = vi.hoisted(() => ({ remove: 0 }));

vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>();
  return {
    ...actual,
    rmSync: (...args: Parameters<typeof actual.rmSync>) => {
      if (faults.remove > 0) {
        faults.remove -= 1;
        throw Object.assign(new Error('EBUSY: resource busy or locked'), { code: 'EBUSY' });
      }
      actual.rmSync(...args);
    },
  };
});

afterEach(() => {
  faults.remove = 0;
});

const SUBSCRIPTION = '00000000-0000-0000-0000-00000000000b';
const WORKSPACE_ID = '00000000-0000-0000-0000-00000000000c';
const START = new Date('2026-09-23T08:00:00Z');
const RUN = 'job-agentx-stg-operator-7x2kq9m';
/** Plain words a test can look for in everything said and sent; never a real business. */
const NAME = 'Zephyrine Trading Test Co';
/** An ID an earlier run gave. */
const EARLIER_ID = '0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b';

const ARM = `https://management.azure.com/subscriptions/${SUBSCRIPTION}/resourceGroups/rg-agentx-staging/providers`;
const JOB_URL = `${ARM}/Microsoft.App/jobs/job-agentx-stg-operator?api-version=${JOBS_API}`;
const RESTORE_URL = `${ARM}/Microsoft.App/jobs/job-agentx-stg-chain-restore?api-version=${JOBS_API}`;
const API_URL = `${ARM}/Microsoft.App/containerApps/ca-agentx-stg-api?api-version=${JOBS_API}`;
const WORKSPACE_URL = `${ARM}/Microsoft.OperationalInsights/workspaces/log-agentx-stg?api-version=2025-02-01`;

/**
 * Names assembled from their words, so no test line pairs a secret's name with
 * a quoted value: the shape GitGuardian reads as a password (PRs #27 and #28).
 */
const setting = (...words: readonly string[]): string => words.join('_');
const secret = (...words: readonly string[]): string => words.join('-');

const image = (digit: string): string => `ghcr.io/shahbaz242630/agent-x@sha256:${digit.repeat(64)}`;
const commit = (digit: string): string => digit.repeat(40);

const IDENTITY = `/subscriptions/${SUBSCRIPTION}/resourceGroups/rg-agentx-staging/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-agentx-stg-operator`;
/** The job's secrets but its request, as Azure gives them back: references to the vault. */
const REFERENCES = [secret('db', 'app', 'password'), secret('key', 'audit', 'mac', 'v1')].map((name) => ({
  identity: IDENTITY,
  keyVaultUrl: `https://kv-agentx-stg-test.vault.azure.net/secrets/${name}`,
  name,
}));

/** The operator's container as Azure gives it back (read S42), with made-up values. */
const operatorContainer = (on: string, build: string) => ({
  args: ['--request', '/mnt/secrets/operator-request'],
  command: ['node', 'apps/operator/src/main.ts'],
  env: [
    { name: 'AGENTX_ENV', value: 'staging' },
    { name: 'AGENTX_RELEASE', value: build },
    { name: 'AGENTX_DB_HOST', value: 'db.example.invalid' },
    { name: 'AGENTX_DB_NAME', value: 'agentx' },
    { name: 'AGENTX_KEYS_DIR', value: '/mnt/secrets' },
    { name: 'AGENTX_DB_USER', value: 'agentx_app' },
    { name: setting('AGENTX', 'DB', 'PASSWORD', 'FILE'), value: `/mnt/secrets/${secret('db', 'app', 'password')}` },
  ],
  image: on,
  name: 'operator',
  resources: { cpu: 0.5, memory: '1Gi' },
  volumeMounts: [{ mountPath: '/mnt/secrets', volumeName: 'secrets' }],
});

/** The chain repair's container (4D2e E10): the operator's, running its own command on its own request. */
const restoreContainer = (on: string, build: string) => ({
  ...operatorContainer(on, build),
  name: 'chain-restore',
  command: ['node', 'apps/operator/src/chain-restore-main.ts'],
  args: ['--request', `/mnt/secrets/${RESTORE_REQUEST_SECRET}`],
});

/** The address a first admin's link starts with: never a real domain in the repository. */
const ORIGIN = 'https://app.example.test';

/** The API's container, as a release reads it. */
const apiContainer = (on: string, build: string, origin: string | null = ORIGIN) => ({
  name: 'api',
  image: on,
  command: ['node', 'apps/api/src/main.ts'],
  args: [],
  env: [
    { name: 'AGENTX_ENV', value: 'staging' },
    { name: 'AGENTX_RELEASE', value: build },
    ...(origin === null ? [] : [{ name: 'AGENTX_PUBLIC_ORIGIN', value: origin }]),
  ],
  resources: { cpu: 0.5, memory: '1Gi', ephemeralStorage: '2Gi' },
  volumeMounts: [{ mountPath: '/mnt/secrets', volumeName: 'secrets' }],
});

/** A row of the log query: when, where from, the platform's reason, the text. */
type Row = readonly [string, string, string, string];

const TERMINATED: Row = [
  '2026-09-23T08:02:12.6002662Z',
  'platform',
  'ContainerTerminated',
  "Container 'operator' was terminated with exit code '0' and reason 'ProcessExited'",
];
const said = (fields: Readonly<Record<string, unknown>>): Row => [
  '2026-09-23T08:02:12.4133012Z',
  'stdout',
  '',
  JSON.stringify({ level: 'info', service: 'operator', ...fields }),
];

/** How a run ends, and what its lines say, for the ID its request names. */
type Ending =
  | 'created'
  | 'activity-exported'
  | 'done-before'
  | 'no-request'
  | 'refused'
  | 'failed'
  | 'created-other'
  | 'done-before-other'
  | 'created-then-failed'
  | 'silent'
  | 'invited'
  | 'invited-done-before'
  | 'invited-other'
  | 'invite-refused'
  | 'copy-holds'
  | 'copy-broken'
  | 'check-refused'
  | 'exported'
  | 'exported-there-already'
  | 'exported-other'
  | 'export-unwritten'
  | 'export-refused'
  | 'no-store'
  | 'resumed'
  | 'resumed-told-before'
  | 'resumed-partly-told'
  | 'resumed-untold'
  | 'resumed-by-another'
  | 'paused-as-born'
  | 'resume-refused'
  | 'resumed-other'
  | 'planned'
  | 'plan-refused'
  | 'plan-copy-broken'
  | 'restored'
  | 'restored-other'
  | 'restore-plan'
  | 'restore-stale'
  | 'restore-signing'
  | 'restore-moved'
  | 'restore-unverified'
  | 'restore-unknown'
  | 'restore-done-before'
  | 'restore-settings'
  | 'restored-old'
  | 'rebased'
  | 'rebased-shorter'
  | 'rebased-unrecorded'
  | 'rebased-already-recorded'
  | 'rebase-recorded'
  | 'rebase-done-already'
  | 'rebase-done-unrecorded'
  | 'rebase-done-other'
  | 'rebase-store'
  | 'rebase-not-needed'
  | 'rebase-not-needed-unanchored'
  | 'rebase-broken'
  | 'rebase-head-differs'
  | 'rebase-unknown'
  | 'rebased-other'
  | 'state-planned'
  | 'state-plan-refused'
  | 'state-plan-copy-broken'
  | 'states-restored'
  | 'state-restore-plan'
  | 'state-restore-stale'
  | 'state-restore-moved'
  | 'state-restore-write'
  | 'state-restore-unverified'
  | 'state-restore-unknown'
  | 'state-restore-done-before';

/** The organisation an audit export is for. */
const EXPORT_ORG = '0199a1b2-c3d4-7e5f-8a6b-00000000000e';

/** Another request's ID, as if that request had run in this one's place. */
const OTHER_ID = '0199a1b2-c3d4-7e5f-8a6b-000000000001';

/** A repaired chain's head, as a rebase names it (4D2e E11). */
const HEAD_HASH_HEX = 'cd'.repeat(32);

/** The line a rebase's run ends with when it is written, for its ID, with `more` in place. */
const rebasedLine = (id: string, more: Readonly<Record<string, unknown>>): Readonly<Record<string, unknown>> => ({
  event: 'operator.chain_rebased',
  rebaseId: id,
  chain: 'organisation',
  seq: '9',
  headHash: HEAD_HASH_HEX,
  anchorSeq: '7',
  shorterBy: '0',
  reason: 'repaired',
  recorded: 'recorded',
  ...more,
});

/** A refused rebase's line, for its ID. */
const rebaseRefused = (id: string, more: Readonly<Record<string, unknown>>): Row =>
  said({ event: 'operator.chain_rebase_refused', rebaseId: id, problem: null, seq: null, ...more });

const RUN_LINES: Readonly<Record<Ending, (id: string) => readonly Row[]>> = {
  created: (id) => [
    said({ event: 'operator.starting' }),
    said({ event: 'operator.organization_created', orgId: id }),
    TERMINATED,
  ],
  'done-before': (id) => [
    said({ event: 'operator.starting' }),
    said({ event: 'operator.done_before', orgId: id }),
    TERMINATED,
  ],
  'no-request': () => [said({ event: 'operator.refused', problems: [NO_REQUEST_PROBLEM] }), TERMINATED],
  refused: () => [said({ event: 'operator.refused', problems: ['the name starts or ends with a space'] }), TERMINATED],
  failed: (id) => [
    said({ event: 'operator.starting' }),
    ['2026-09-23T08:02:12.5Z', 'stderr', '', 'a line that is not JSON'],
    said({ event: 'operator.failed', orgId: id }),
    TERMINATED,
  ],
  'created-other': () => [
    said({ event: 'operator.starting' }),
    said({ event: 'operator.organization_created', orgId: OTHER_ID }),
    TERMINATED,
  ],
  'done-before-other': () => [said({ event: 'operator.done_before', orgId: OTHER_ID }), TERMINATED],
  // Created, and then stopped before it could end well (its end cut short).
  'created-then-failed': (id) => [said({ event: 'operator.organization_created', orgId: id }), TERMINATED],
  // Azure delivered none of the command's own lines.
  silent: () => [TERMINATED],
  invited: (id) => [
    said({ event: 'operator.starting' }),
    said({ event: 'operator.first_admin_invited', invitationId: id }),
    TERMINATED,
  ],
  'invited-done-before': (id) => [said({ event: 'operator.done_before', invitationId: id }), TERMINATED],
  'invited-other': () => [said({ event: 'operator.first_admin_invited', invitationId: OTHER_ID }), TERMINATED],
  'invite-refused': (id) => [
    said({
      event: 'operator.refused',
      invitationId: id,
      problems: ['the organisation has members: its admins invite, not the operator'],
    }),
    TERMINATED,
  ],
  'copy-holds': () => [
    said({ event: 'operator.starting' }),
    said({
      event: 'operator.restore_check_done',
      chainsChecked: 4,
      chainsHeld: 4,
      platformCopySeq: 9,
      platformLiveSeq: 11,
      copyOrganizations: 3,
      newSinceCopy: 1,
      problems: [],
      problemCount: 0,
    }),
    TERMINATED,
  ],
  'copy-broken': () => [
    said({
      event: 'operator.restore_check_failed',
      problems: ["platform on the live server, from the copy's head: anchor at 7"],
      problemCount: 3,
    }),
    TERMINATED,
  ],
  'check-refused': () => [
    said({ event: 'operator.refused', problems: ['a connection is not read-only, so nothing was read'] }),
    TERMINATED,
  ],
  exported: (id) => [
    said({ event: 'operator.starting' }),
    said({
      event: 'operator.audit_exported',
      exportId: id,
      events: 42,
      file: `${EXPORT_ORG}/${id}.ndjson`,
      write: 'written',
      bytes: 9001,
      sha256: 'ab'.repeat(32),
    }),
    TERMINATED,
  ],
  'activity-exported': (id) => [
    said({
      event: 'operator.activity_exported',
      exportId: id,
      requests: 7,
      file: `${EXPORT_ORG}/activity-${id}.ndjson`,
      write: 'written',
      bytes: 512,
      sha256: 'cd'.repeat(32),
    }),
    TERMINATED,
  ],
  'exported-there-already': (id) => [
    said({
      event: 'operator.audit_exported',
      exportId: id,
      events: 42,
      recordedBefore: true,
      file: `${EXPORT_ORG}/${id}.ndjson`,
      write: 'there_already',
    }),
    TERMINATED,
  ],
  'exported-other': () => [
    said({ event: 'operator.audit_exported', exportId: OTHER_ID, write: 'written', file: 'x' }),
    TERMINATED,
  ],
  'export-unwritten': (id) => [
    said({
      event: 'operator.export_unwritten',
      exportId: id,
      problems: ['the blob service answered 503 (ServerBusy)'],
    }),
    TERMINATED,
  ],
  'export-refused': (id) => [
    said({ event: 'operator.refused', exportId: id, problems: ["the organisation isn't in the directory"] }),
    TERMINATED,
  ],
  'no-store': () => [said({ event: 'operator.refused', problems: [NO_STORE_PROBLEM] }), TERMINATED],
  resumed: (id) => [
    said({ event: 'operator.starting' }),
    said({ event: 'operator.handoff_resumed', platformEventId: id, platformSeq: 12 }),
    said({ event: 'operator.handoff_told', platformEventId: id, organizations: 3, told: 3, toldBefore: 0, failed: 0 }),
    TERMINATED,
  ],
  'resumed-told-before': (id) => [
    said({ event: 'operator.handoff_unchanged', platformEventId: id, paused: false, inForce: id }),
    said({ event: 'operator.handoff_told', platformEventId: id, organizations: 3, told: 1, toldBefore: 2, failed: 0 }),
    TERMINATED,
  ],
  'resumed-partly-told': (id) => [
    said({ event: 'operator.handoff_resumed', platformEventId: id, platformSeq: 12 }),
    said({ event: 'operator.handoff_told', platformEventId: id, organizations: 3, told: 2, toldBefore: 0, failed: 1 }),
    TERMINATED,
  ],
  'resumed-untold': (id) => [
    said({ event: 'operator.handoff_resumed', platformEventId: id, platformSeq: 12 }),
    said({ event: 'operator.failed', platformEventId: id }),
    TERMINATED,
  ],
  'resumed-by-another': (id) => [
    said({ event: 'operator.handoff_unchanged', platformEventId: id, paused: false, inForce: OTHER_ID }),
    TERMINATED,
  ],
  'paused-as-born': (id) => [
    said({ event: 'operator.handoff_unchanged', platformEventId: id, paused: true, inForce: null }),
    TERMINATED,
  ],
  'resume-refused': (id) => [
    said({
      event: 'operator.refused',
      platformEventId: id,
      problems: ["the hand-off pause's record can't be verified, so nothing was changed"],
    }),
    TERMINATED,
  ],
  planned: (id) => [
    said({
      event: 'operator.chain_recovery_planned',
      planId: id,
      digest: 'ab'.repeat(32),
      putBack: 2,
      replaced: 1,
      removed: 0,
      headReplaced: true,
      forkDiscarded: false,
    }),
    TERMINATED,
  ],
  'plan-refused': (id) => [
    said({ event: 'operator.chain_recovery_refused', planId: id, reason: 'fork', seq: '4', problem: null }),
    TERMINATED,
  ],
  'plan-copy-broken': (id) => [
    said({ event: 'operator.chain_recovery_refused', planId: id, reason: 'copy_broken', seq: '2', problem: 'mac' }),
    TERMINATED,
  ],
  restored: (id) => [
    said({ event: 'operator.chain_restore_owner_login', restoreId: id }),
    said({
      event: 'operator.chain_restored',
      restoreId: id,
      putBack: 2,
      replaced: 1,
      removed: 0,
      endsAt: '9',
      endsAtHash: 'cd'.repeat(32),
      holdKept: true,
    }),
    TERMINATED,
  ],
  'restored-other': () => [said({ event: 'operator.chain_restored', restoreId: OTHER_ID }), TERMINATED],
  'restore-plan': (id) => [
    said({ event: 'operator.chain_restore_refused', restoreId: id, reason: 'plan', planRefused: 'fork', seq: '4' }),
    TERMINATED,
  ],
  'restore-stale': (id) => [
    said({ event: 'operator.chain_restore_refused', restoreId: id, reason: 'stale' }),
    TERMINATED,
  ],
  'restore-signing': (id) => [
    said({ event: 'operator.chain_restore_refused', restoreId: id, reason: 'signing_start' }),
    TERMINATED,
  ],
  'restore-moved': (id) => [
    said({ event: 'operator.chain_restore_refused', restoreId: id, reason: 'moved' }),
    TERMINATED,
  ],
  'restore-unverified': (id) => [
    said({ event: 'operator.chain_restore_refused', restoreId: id, reason: 'unverified', problem: 'mac', seq: '3' }),
    TERMINATED,
  ],
  'restore-unknown': (id) => [
    said({ event: 'operator.chain_restore_refused', restoreId: id, reason: 'something_new' }),
    TERMINATED,
  ],
  'restore-done-before': (id) => [said({ event: 'operator.done_before', restoreId: id }), TERMINATED],
  'restore-settings': () => [
    said({
      event: 'operator.refused',
      problems: ['AGENTX_DB_USER must be agentx_owner: only the owner may repair a chain'],
    }),
    TERMINATED,
  ],
  'restored-old': (id) => [
    said({ event: 'operator.chain_restored', restoreId: id, putBack: 1, replaced: 0, removed: 0, endsAt: '9' }),
    TERMINATED,
  ],
  rebased: (id) => [said(rebasedLine(id, {})), TERMINATED],
  'rebased-shorter': (id) => [said(rebasedLine(id, { shorterBy: '2' })), TERMINATED],
  'rebased-unrecorded': (id) => [said(rebasedLine(id, { recorded: 'failed' })), TERMINATED],
  'rebased-already-recorded': (id) => [said(rebasedLine(id, { recorded: 'already' })), TERMINATED],
  'rebase-recorded': (id) => [said({ event: 'operator.rebase_recorded', rebaseId: id }), TERMINATED],
  'rebase-done-already': (id) => [
    said({ event: 'operator.done_before', command: 'chain-rebase', rebaseId: id, recorded: 'already' }),
    TERMINATED,
  ],
  'rebase-done-unrecorded': (id) => [
    said({ event: 'operator.done_before', command: 'chain-rebase', rebaseId: id, recorded: 'failed' }),
    TERMINATED,
  ],
  'rebase-done-other': (id) => [
    said({ event: 'operator.done_before', command: 'chain-rebase', rebaseId: id, recorded: null }),
    TERMINATED,
  ],
  'rebase-store': (id) => [rebaseRefused(id, { reason: 'store' }), TERMINATED],
  'rebase-not-needed': (id) => [rebaseRefused(id, { reason: 'not_needed', seq: '12' }), TERMINATED],
  'rebase-not-needed-unanchored': (id) => [rebaseRefused(id, { reason: 'not_needed', seq: null }), TERMINATED],
  'rebase-broken': (id) => [rebaseRefused(id, { reason: 'broken', problem: 'mac', seq: '4' }), TERMINATED],
  'rebase-head-differs': (id) => [rebaseRefused(id, { reason: 'head_differs', seq: '11' }), TERMINATED],
  'rebase-unknown': (id) => [rebaseRefused(id, { reason: 'something_new' }), TERMINATED],
  'rebased-other': () => [said(rebasedLine(OTHER_ID, {})), TERMINATED],
  'state-planned': (id) => [
    said({
      event: 'operator.state_recovery_planned',
      planId: id,
      digest: 'ab'.repeat(32),
      putBack: 2,
      removed: 1,
      objects: 40,
    }),
    TERMINATED,
  ],
  'state-plan-refused': (id) => [
    said({
      event: 'operator.state_recovery_refused',
      planId: id,
      reason: 'newer_than_copy',
      subjectType: 'agent',
      objectId: OTHER_ID,
      problem: null,
    }),
    TERMINATED,
  ],
  'state-plan-copy-broken': (id) => [
    said({
      event: 'operator.state_recovery_refused',
      planId: id,
      reason: 'chain_broken',
      subjectType: null,
      objectId: null,
      problem: 'link at 4',
    }),
    TERMINATED,
  ],
  'states-restored': (id) => [
    said({ event: 'operator.states_restored', restoreId: id, putBack: 2, removed: 1, holdKept: true }),
    TERMINATED,
  ],
  'state-restore-plan': (id) => [
    said({ event: 'operator.state_restore_refused', restoreId: id, reason: 'plan', planRefused: 'newer_than_copy' }),
    TERMINATED,
  ],
  'state-restore-stale': (id) => [
    said({ event: 'operator.state_restore_refused', restoreId: id, reason: 'stale' }),
    TERMINATED,
  ],
  'state-restore-moved': (id) => [
    said({
      event: 'operator.state_restore_refused',
      restoreId: id,
      reason: 'moved',
      subjectType: 'agent',
      objectId: OTHER_ID,
    }),
    TERMINATED,
  ],
  'state-restore-write': (id) => [
    said({ event: 'operator.state_restore_refused', restoreId: id, reason: 'write_refused', code: '23503' }),
    TERMINATED,
  ],
  'state-restore-unverified': (id) => [
    said({ event: 'operator.state_restore_refused', restoreId: id, reason: 'unverified', check: 'whole' }),
    TERMINATED,
  ],
  'state-restore-unknown': (id) => [
    said({ event: 'operator.state_restore_refused', restoreId: id, reason: 'something_new' }),
    TERMINATED,
  ],
  'state-restore-done-before': (id) => [said({ event: 'operator.done_before', restoreId: id }), TERMINATED],
  'resumed-other': () => [
    said({ event: 'operator.handoff_resumed', platformEventId: OTHER_ID }),
    said({ event: 'operator.handoff_told', platformEventId: OTHER_ID, told: 3, toldBefore: 0, failed: 0 }),
    TERMINATED,
  ],
};

/** The endings whose command exits 0, so Azure ends the run Succeeded. */
const SUCCEEDS: ReadonlySet<Ending> = new Set([
  'created',
  'created-other',
  'silent',
  'invited',
  'invited-other',
  'copy-holds',
  'exported',
  'exported-there-already',
  'exported-other',
  'resumed',
  'resumed-told-before',
  'resumed-by-another',
  'paused-as-born',
  'resumed-other',
  'restored-old',
  'rebased',
  'rebased-shorter',
  'rebased-already-recorded',
  'rebase-recorded',
  'rebased-other',
  'planned',
  'restored',
  'restored-other',
  'state-planned',
  'states-restored',
]);

/** How Azure settles a change: the state it ends in, or never. */
type Settles = 'Succeeded' | 'Failed' | 'Canceled' | 'never';

interface Script {
  /** What the job and the API run before anything. */
  readonly jobImage?: string;
  readonly jobBuild?: string;
  readonly apiImage?: string;
  readonly apiBuild?: string;
  /** The job's state before anything, from an earlier change. */
  readonly state?: string;
  /** A change to the job's answer, for the jobs this tool must refuse. */
  readonly job?: (answer: Record<string, unknown>) => void;
  /** The job's runs, as `execution list` gives them. */
  readonly runs?: unknown;
  /** How many readings after a PATCH still show the job as it was, and how each PATCH settles, in order. */
  readonly lag?: number;
  readonly settles?: readonly Settles[];
  /** Another deploy's change to the job landing just before this tool's first. */
  readonly interloper?: boolean;
  /** How many readings show another change to the job going, once the run has started. */
  readonly busy?: number;
  /** The workspace refusing the log query. */
  readonly logRefused?: boolean;
  /** The API holding no public origin (B4-6b), or this one. */
  readonly noOrigin?: boolean;
  readonly origin?: string;
  /** Each PATCH's CLI status, in order: 0 sends it. */
  readonly patchStatus?: readonly number[];
  readonly startStatus?: number;
  /** The states `execution show` gives, the last repeated. */
  readonly states?: readonly string[];
  readonly ending?: Ending;
  /** The chain repair's job (4D2e E10) in place of the operator's. */
  readonly restore?: boolean;
}

/** A change Azure is settling: the readings left that show the job as it was, then the change. */
interface Settling {
  left: number;
  applied: boolean;
  readonly settles: Settles;
  readonly apply: () => void;
}

/** An az call that succeeded, answering with the value as JSON. */
const json = (value: unknown): AzResult => ({ status: 0, stdout: JSON.stringify(value), stderr: '' });

/**
 * Azure as the runner meets it: the job and the API, and every call recorded.
 * A change to the job made while another is still going is refused, as Azure
 * refuses one.
 */
class FakeAzure implements Az {
  readonly calls: (readonly string[])[] = [];
  /** Each PATCH as it was sent: the file's text, and its JSON. */
  readonly sent: { readonly text: string; readonly body: Record<string, unknown>; readonly file: string }[] = [];
  /** What the job holds as its request, and held when its run started. */
  request = NO_REQUEST;
  heldAtStart: string | undefined;
  container: unknown;
  state: string;
  modified = '2026-09-22T17:20:12.062971';
  readonly #script: Script;
  #settling: Settling | undefined;
  #busy = 0;
  #changes = 0;
  #readings = 0;

  /** The job's own address and the secret its request is in: the operator's, or the chain repair's. */
  readonly #jobUrl: string;
  readonly #secret: string;
  /** The name Azure gives a run of the job. */
  readonly #run: string;

  constructor(script: Script) {
    this.#script = script;
    const made = script.restore === true ? restoreContainer : operatorContainer;
    this.container = made(script.jobImage ?? image('a'), script.jobBuild ?? commit('a'));
    this.#jobUrl = script.restore === true ? RESTORE_URL : JOB_URL;
    this.#secret = script.restore === true ? RESTORE_REQUEST_SECRET : REQUEST_SECRET;
    this.#run = script.restore === true ? 'job-agentx-stg-chain-restore-7x2kq9m' : RUN;
    this.state = script.state ?? 'Succeeded';
  }

  interactive(): number | null {
    throw new Error('the operator runner never runs the CLI interactively');
  }

  run(args: readonly string[]): AzResult {
    this.calls.push(args);
    const script = this.#script;
    if (args[0] === 'rest') return this.#rest(args);
    const words = args.filter((arg) => !arg.startsWith('-')).slice(0, 4);
    switch (words.join(' ')) {
      case 'account show json':
        return json({ name: 'Azure subscription 1', id: SUBSCRIPTION });
      case 'containerapp job execution list':
        return json('runs' in script ? script.runs : [{ name: 'old', properties: { status: 'Succeeded' } }]);
      case `containerapp job start ${SUBSCRIPTION}`:
        if (script.startStatus !== undefined) {
          return { status: script.startStatus, stdout: '', stderr: 'ERROR: Conflict({"error":{"code":"JobBusy"}})' };
        }
        this.heldAtStart = this.request;
        this.#busy = script.busy ?? 0;
        return json({ id: '/subscriptions/x', name: this.#run });
      case 'containerapp job execution show': {
        const states = script.states ?? [SUCCEEDS.has(script.ending ?? 'created') ? 'Succeeded' : 'Failed'];
        const state = states[Math.min(this.#readings, states.length - 1)];
        this.#readings += 1;
        return json({
          name: this.#run,
          properties: { status: state, startTime: '2026-09-23T08:01:43+00:00', endTime: '2026-09-23T08:02:21+00:00' },
        });
      }
      default:
        throw new Error(`unexpected az ${args.join(' ')}`);
    }
  }

  /** A REST call: a PATCH of the job, a GET of the job, the API or the workspace, or the log query. */
  #rest(args: readonly string[]): AzResult {
    const script = this.#script;
    const method = args[args.indexOf('--method') + 1];
    const url = args[args.indexOf('--url') + 1];
    if (method === 'patch') return this.#patch(args, url);
    if (method === 'get' && url === this.#jobUrl) return json(this.#job());
    if (method === 'get' && url === API_URL) return json(this.#api());
    if (method === 'get' && url === WORKSPACE_URL) return json({ properties: { customerId: WORKSPACE_ID } });
    if (method === 'post' && url === `https://api.loganalytics.azure.com/v1/workspaces/${WORKSPACE_ID}/query`) {
      if (script.logRefused === true) {
        return { status: 1, stdout: '', stderr: 'ERROR: Forbidden({"error":{"code":"InsufficientAccessError"}})' };
      }
      return json(this.#log());
    }
    throw new Error(`unexpected az ${args.join(' ')}`);
  }

  /** The API as a GET gives it: its image, build and public origin as the script says. */
  #api(): Record<string, unknown> {
    const script = this.#script;
    return {
      properties: {
        provisioningState: 'Succeeded',
        template: {
          containers: [
            apiContainer(
              script.apiImage ?? image('b'),
              script.apiBuild ?? commit('b'),
              script.noOrigin === true ? null : (script.origin ?? ORIGIN),
            ),
          ],
        },
      },
      tags: {},
    };
  }

  /** The job as a GET gives it: never a secret's value, and a change being settled shown as Azure shows it. */
  #job(): Record<string, unknown> {
    const settling = this.#settling;
    if (settling !== undefined) {
      if (settling.left > 0) {
        settling.left -= 1;
      } else if (!settling.applied) {
        settling.apply();
        settling.applied = true;
        this.modified = `2026-09-23T08:0${String(this.#changes)}:00.000000`;
        this.state = 'InProgress';
      } else if (settling.settles !== 'never') {
        this.state = settling.settles;
        this.#settling = undefined;
      }
    }
    const going = this.#busy > 0;
    if (going) this.#busy -= 1;
    const answer: Record<string, unknown> = {
      id: '/subscriptions/x',
      name: jobName(this.#script.restore === true ? 'chain-restore' : 'operator'),
      properties: {
        provisioningState: going ? 'InProgress' : this.state,
        configuration: {
          replicaTimeout: 300,
          replicaRetryLimit: 0,
          triggerType: 'Manual',
          secrets: [...REFERENCES, { name: this.#secret }],
        },
        template: {
          containers: [this.container],
          volumes: [{ name: 'secrets', storageType: 'Secret' }],
        },
      },
      systemData: { lastModifiedAt: this.modified },
    };
    this.#script.job?.(answer);
    return answer;
  }

  #patch(args: readonly string[], url: string | undefined): AzResult {
    expect(url).toBe(this.#jobUrl);
    const body = args[args.indexOf('--body') + 1] ?? '';
    expect(body.startsWith('@')).toBe(true);
    const file = body.slice(1);
    const text = readFileSync(file, 'utf8');
    const parsed = JSON.parse(text) as Record<string, unknown>;
    this.sent.push({ text, body: parsed, file });
    const index = this.#changes;
    this.#changes += 1;
    if (this.#settling !== undefined || this.#busy > 0) {
      return {
        status: 1,
        stdout: '',
        stderr:
          'ERROR: Conflict({"error":{"code":"ContainerAppOperationInProgress","message":"another operation is in progress"}})',
      };
    }
    const status = this.#script.patchStatus?.[index] ?? 0;
    if (status !== 0) {
      return {
        status,
        stdout: '',
        stderr: `ERROR: Bad Request({"error":{"code":"InvalidParameter","message":"${text}"}})`,
      };
    }
    if (index === 0 && this.#script.interloper === true) {
      // Another deploy's change lands first: the job's last change moves on, with this tool's still to come.
      this.modified = '2026-09-23T07:59:30.000000';
      this.state = 'Succeeded';
    }
    const properties = parsed.properties as {
      configuration: { secrets: { name: string; value?: string }[] };
      template?: { containers: unknown[] };
    };
    this.#settling = {
      left: this.#script.lag ?? 1,
      applied: false,
      settles: this.#script.settles?.[index] ?? 'Succeeded',
      apply: () => {
        this.request = properties.configuration.secrets.find((each) => each.name === this.#secret)?.value ?? '';
        if (properties.template !== undefined) this.container = properties.template.containers[0];
      },
    };
    return { status: 0, stdout: '', stderr: '' };
  }

  /** The run's lines, for the ID its request named when it started. */
  #log(): unknown {
    const words = JSON.parse(this.heldAtStart ?? '[]') as string[];
    // The ID a request names: an organisation's fifth word, an invitation's seventh, an export's eleventh.
    const at =
      {
        'invite-first-admin': 6,
        'audit-export': 10,
        'activity-export': 10,
        'chain-restore': 8,
        'state-restore': 8,
        'chain-rebase': 12,
      }[String(words[0])] ?? 4;
    const id = String(words[at]);
    const rows = RUN_LINES[this.#script.ending ?? 'created'](id);
    return {
      tables: [
        {
          columns: [{ name: 'TimeGenerated' }, { name: 'Source' }, { name: 'Reason' }, { name: 'Text' }],
          rows,
        },
      ],
    };
  }

  /** The commands, by their first words, in the order they ran. */
  get sequence(): string[] {
    return this.calls.map((call) => {
      if (call[0] !== 'rest') return call.slice(0, call[2] === 'execution' ? 4 : 3).join(' ');
      const url = call[call.indexOf('--url') + 1] ?? '';
      const what =
        url === this.#jobUrl ? 'job' : url === API_URL ? 'api' : url.includes('/query') ? 'log' : 'workspace';
      return `${call[2] ?? ''} ${what}`;
    });
  }
}

/** One run of the runner, with a clock that moves only when it sleeps. */
async function run(argv: readonly string[], script: Script = {}) {
  const az = new FakeAzure(script);
  const lines: string[] = [];
  const slept: number[] = [];
  let now = START.getTime();
  const status = await createOrganization(parseArguments(argv), {
    az,
    say: (line) => lines.push(line),
    now: () => new Date(now),
    sleep: (ms) => {
      slept.push(ms);
      now += ms;
      return Promise.resolve();
    },
  }).then(
    (value) => ({ value, error: undefined }),
    (error: unknown) => ({ value: undefined, error }),
  );
  return { status: status.value, error: status.error, az, said: lines, slept };
}

const create = ['create-organization', '--name', NAME];

describe('parseArguments', () => {
  it('reads a name, and an earlier run ID when one is given', () => {
    expect(parseArguments(create)).toEqual({ name: NAME, id: undefined });
    expect(parseArguments([...create, '--id', EARLIER_ID])).toEqual({ name: NAME, id: EARLIER_ID });
  });

  it('refuses anything else, repeating nothing typed', () => {
    const shape = 'say create-organization --name <name> [--id <ID>], the name as one argument, and nothing else';
    for (const [argv, message] of [
      [[], shape],
      [['create-organization'], shape],
      [['create-organization', '--name'], shape],
      [['create-organization', '--name', ''], shape],
      [['delete-organization', '--name', NAME], shape],
      [['create-organization', '--title', NAME], shape],
      [['create-organization', '--name', 'Zephyrine', 'Trading'], shape],
      [[...create, '--id'], shape],
      [[...create, '--org', EARLIER_ID], shape],
      [[...create, '--id', EARLIER_ID, '--force'], shape],
      [[...create, '--id', EARLIER_ID.toUpperCase()], '--id takes the ID an earlier run gave: a UUIDv7, in lower case'],
      [
        [...create, '--id', '6f1c2d3e-4a5b-4c6d-8e7f-0a1b2c3d4e5f'],
        '--id takes the ID an earlier run gave: a UUIDv7, in lower case',
      ],
    ] as const) {
      expect(() => parseArguments(argv)).toThrow(new UsageError(message));
    }
  });

  it(`refuses a name that makes the request longer than the ${String(REQUEST_LIMIT_BYTES)} bytes the operator reads`, () => {
    const fits = 'Q'.repeat(REQUEST_LIMIT_BYTES - createOrganizationRequest('', EARLIER_ID).length);
    expect(parseArguments(['create-organization', '--name', fits]).name).toBe(fits);
    expect(() => parseArguments(['create-organization', '--name', `${fits}Q`])).toThrow(
      new UsageError(
        `the name makes the request longer than the ${String(REQUEST_LIMIT_BYTES)} bytes the operator reads`,
      ),
    );
    // Counted in UTF-8, as the operator reads it: two bytes a letter here.
    const accented = String.fromCharCode(0xe9).repeat(Math.floor(fits.length / 2) + 1);
    expect(() => parseArguments(['create-organization', '--name', accented])).toThrow(UsageError);
  });
});

/** The ID a run's request named, as the job held it when the run started. */
const idHeld = (az: FakeAzure): string => String((JSON.parse(az.heldAtStart ?? '[]') as string[])[4]);

/** The ID the tool said it made, from its second line. */
const idSaid = (lines: readonly string[]): string => /ID is (\S+)\. /.exec(lines[1] ?? '')?.[1] ?? '';

/** What the tool says of a request that may still be on the job, and what takes it off. */
const mayStillHold = (id: string): string =>
  `The request may still be on job-agentx-stg-operator. It names ${id}, so it can't make a second organisation. Take it off by running the same command again with --id ${id}, or by deploying the apps (deploy.ts apps).`;

/** The tool's last word on any failure once the ID is made. */
const tryAgain = (id: string): string =>
  `To find out what happened, and finish it if it didn't: run the same command again with --id ${id}. If the organisation exists, that run ends "Already done"; none is made twice.`;

describe('creating an organisation', () => {
  it("writes the request with the API's build, runs it, puts [] back and says it was created", async () => {
    const done = await run(create);

    expect(done.error).toBeUndefined();
    expect(done.status).toBe(0);
    expect(done.az.sequence).toEqual([
      'account show --output',
      'get job',
      'get api',
      'containerapp job execution list',
      'patch job',
      'get job',
      'get job',
      'get job',
      // The start looks again for a run going, then starts the job as it is.
      'containerapp job execution list',
      'containerapp job start',
      'containerapp job execution show',
      'get job',
      'patch job',
      'get job',
      'get job',
      'get job',
      'get workspace',
      'post log',
      'post log',
    ]);
    const [write, clear] = done.az.sent;
    const id = idHeld(done.az);
    expect(id).toMatch(UUID_V7);
    // The run started holding this request, and the job holds none now.
    expect(done.az.heldAtStart).toBe(createOrganizationRequest(NAME, id));
    expect(done.az.request).toBe(NO_REQUEST);
    // One PATCH: every vault reference as it was read, the request, and the container on the API's build.
    expect(write?.body).toEqual({
      properties: {
        configuration: {
          secrets: [...REFERENCES, { name: REQUEST_SECRET, value: createOrganizationRequest(NAME, id) }],
        },
        template: { containers: [operatorContainer(image('b'), commit('b'))] },
      },
    });
    // Then the request off again, the references as they are, and the container left alone.
    expect(clear?.body).toEqual({
      properties: { configuration: { secrets: [...REFERENCES, { name: REQUEST_SECRET, value: NO_REQUEST }] } },
    });
    expect(done.az.container).toEqual(operatorContainer(image('b'), commit('b')));
    expect(done.said).toEqual([
      `Signed in to the subscription "Azure subscription 1" (${SUBSCRIPTION}).`,
      `The new organisation's ID is ${id}. If this run's end is unclear, run the same command again with --id ${id}: it can't make a second organisation, and it takes the request off the job at its end.`,
      `Bringing job-agentx-stg-operator to the API's build: image ${image('a')} → ${image('b')}; AGENTX_RELEASE ${commit('a')} → ${commit('b')}.`,
      'Wrote the request onto job-agentx-stg-operator.',
      `Started ${RUN}.`,
      `Waiting for ${RUN} to end (the job gives up after 300 s)...`,
      // Two readings 15 s apart while Azure took the request.
      '  08:00:30 UTC  Succeeded',
      `${RUN} ended Succeeded: started 08:01:43 UTC, ended 08:02:21 UTC (38 s).`,
      'Put [] back on job-agentx-stg-operator: its next run holds no request until one is written.',
      `Reading ${RUN}'s log: Azure delivers a container's lines up to 10 minutes after they are written, so this can take that long...`,
      `${RUN}'s log, 1 from the platform and 2 from the container:`,
      '  08:02:12  stdout    {"level":"info","service":"operator","event":"operator.starting"}',
      `  08:02:12  stdout    {"level":"info","service":"operator","event":"operator.organization_created","orgId":"${id}"}`,
      "  08:02:12  platform  ContainerTerminated: Container 'operator' was terminated with exit code '0' and reason 'ProcessExited'",
      `Created the organisation ${id}.`,
    ]);
  });

  it('sends no container when the job already runs what the API runs, and still starts only once the request is taken', async () => {
    const done = await run(create, { jobImage: image('b'), jobBuild: commit('b') });

    expect(done.status).toBe(0);
    expect(done.az.sent.map((each) => Object.keys(each.body.properties as object))).toEqual([
      ['configuration'],
      ['configuration'],
    ]);
    expect(done.said.filter((line) => line.startsWith('Bringing'))).toEqual([]);
    // Only the time of the job's last change tells the request taken here: the container is the same throughout.
    expect(done.az.heldAtStart).toBe(createOrganizationRequest(NAME, idHeld(done.az)));
  });

  it('never prints the name, never puts it on a command line, and removes the file it was sent in', async () => {
    const done = await run(create);

    expect(done.said.join('\n')).not.toContain('Zephyrine');
    expect(done.az.calls.flat().join(' ')).not.toContain('Zephyrine');
    expect(done.az.sent[0]?.text).toContain('Zephyrine');
    for (const each of done.az.sent) expect(existsSync(each.file)).toBe(false);
  });

  it("says a folder it couldn't remove, and still counts the PATCH Azure took", async () => {
    faults.remove = 1;
    const done = await run(create);
    const folder = path.dirname(done.az.sent[0]?.file ?? '');
    try {
      expect(done.status).toBe(0);
      expect(done.said).toContain(
        `Couldn't remove ${folder}, which holds what was sent: remove it by hand (EBUSY: resource busy or locked).`,
      );
      expect(done.az.heldAtStart).toBe(createOrganizationRequest(NAME, idHeld(done.az)));
    } finally {
      rmSync(folder, { recursive: true, force: true });
    }
  });

  it('sends a name past ASCII as escapes, so it reads the same in any encoding, and it arrives whole', async () => {
    // Arabic, an accented letter, and a letter from beyond the first 65,536 (two UTF-16 units).
    const name = `${String.fromCharCode(0x0645, 0x0624, 0x0633, 0x0633, 0x0629)} Caf${String.fromCharCode(0xe9)} ${String.fromCodePoint(0x1d49c)}`;
    const done = await run(['create-organization', '--name', name]);

    expect(done.status).toBe(0);
    expect(done.az.sent[0]?.text).toMatch(/^[ -~]+$/);
    expect(done.az.heldAtStart).toBe(createOrganizationRequest(name, idHeld(done.az)));
  });

  it('writes the ID given for a retry, and calls a request done before already done', async () => {
    const done = await run([...create, '--id', EARLIER_ID], { ending: 'done-before' });

    expect(done.status).toBe(0);
    expect(done.az.heldAtStart).toBe(createOrganizationRequest(NAME, EARLIER_ID));
    expect(done.said.at(-1)).toBe(
      `Already done: the organisation ${EARLIER_ID} exists from an earlier run of this request, and nothing changed.`,
    );
    expect(done.az.request).toBe(NO_REQUEST);
  });

  it('takes a line saying this ID was created for the truth, even from a run whose end was cut short', async () => {
    const done = await run(create, { ending: 'created-then-failed' });

    expect(done.status).toBe(0);
    expect(done.said.at(-1)).toBe(`Created the organisation ${idHeld(done.az)}.`);
  });

  it('never takes a line about another ID for this one: another request may have run in its place', async () => {
    const other = await run(create, { ending: 'created-other' });
    const id = idHeld(other.az);
    expect(other.status).toBe(1);
    expect(other.said.at(-1)).toBe(
      `The run succeeded, but its lines don't show the organisation ${id} made: they may not all have arrived, or another request ran in this one's place. Run the same command again with --id ${id}, which can't make a second one.`,
    );

    const doneBefore = await run([...create, '--id', EARLIER_ID], { ending: 'done-before-other' });
    expect(doneBefore.status).toBe(1);
    expect(doneBefore.said.at(-1)).toMatch(/^The organisation may not have been created: /);
  });

  it("says so when a run succeeded but none of the command's lines arrived", async () => {
    const done = await run(create, { ending: 'silent' });

    expect(done.status).toBe(1);
    expect(done.said.at(-1)).toMatch(/^The run succeeded, but its lines don't show the organisation /);
  });

  it('says so when the run found no request, Azure not having put it in place in time', async () => {
    const done = await run(create, { ending: 'no-request' });

    expect(done.status).toBe(1);
    expect(done.said.at(-1)).toBe(
      `The run found no request, so nothing changed: Azure hadn't put it in place when the run started. Run the same command again with --id ${idHeld(done.az)}.`,
    );
    expect(done.az.request).toBe(NO_REQUEST);
  });

  it.each(['refused', 'failed'] as const)(
    'reads a run that %s as not created, saying how to try again',
    async (ending) => {
      const done = await run(create, { ending });

      expect(done.status).toBe(1);
      expect(done.said.at(-1)).toBe(
        `The organisation may not have been created: read the lines above. If they leave it unclear, run the same command again with --id ${idHeld(done.az)}, which can't make a second one.`,
      );
      expect(done.az.request).toBe(NO_REQUEST);
    },
  );

  it("puts [] back and says how to wait again when the run doesn't end in time, reading no log", async () => {
    const done = await run(create, { states: ['Running'] });

    expect(done.status).toBe(1);
    expect(done.az.request).toBe(NO_REQUEST);
    expect(done.said).toContain(
      `${RUN} hadn't ended 600 s after the wait began. To wait again: node deploy/azure/jobs.ts wait operator ${RUN}`,
    );
    expect(done.az.sequence).not.toContain('post log');
  });

  it('waits for Azure to take each change, never trusting the state an earlier change left', async () => {
    const done = await run(create, { lag: 3 });

    expect(done.status).toBe(0);
    // After each PATCH: three readings as it was, one taking it, one settled.
    expect(done.az.sequence.slice(4, 10)).toEqual(['patch job', 'get job', 'get job', 'get job', 'get job', 'get job']);
    expect(done.az.heldAtStart).toBe(createOrganizationRequest(NAME, idHeld(done.az)));
  });

  it("waits out another deploy's change landing first, which moves the job's last change but not to its container", async () => {
    const done = await run(create, { interloper: true });

    expect(done.status).toBe(0);
    expect(done.az.heldAtStart).toBe(createOrganizationRequest(NAME, idHeld(done.az)));
  });

  it('waits for another change to the job to end before taking the request off, since Azure refuses one made during it', async () => {
    const done = await run(create, { busy: 2 });

    expect(done.status).toBe(0);
    expect(done.az.request).toBe(NO_REQUEST);
    // After the run: two readings of the other change going, then one idle, and only then the PATCH.
    expect(done.az.sequence.slice(11, 15)).toEqual(['get job', 'get job', 'get job', 'patch job']);
  });
});

describe('what stops it, and what it leaves', () => {
  it.each([
    [
      'still settling an earlier change',
      { state: 'InProgress' },
      'job-agentx-stg-operator is InProgress from an earlier change, so nothing was written: look at it first.',
    ],
    [
      'running a run',
      { runs: [{ name: RUN, properties: { status: 'Running' } }] },
      `job-agentx-stg-operator has runs that haven't ended, so nothing was written: ${RUN} (Running).`,
    ],
  ] as const)('writes nothing to a job %s', async (_what, script, message) => {
    const done = await run(create, script);

    expect(done.error).toMatchObject({ message });
    expect(done.az.sent).toEqual([]);
    expect(done.az.sequence).not.toContain('containerapp job start');
  });

  const NOT_A_REFERENCE =
    'a secret other than its request must be exactly a reference to the vault: a name, a URL and an identity';

  it.each([
    [
      'a container field it would drop',
      (job: Record<string, unknown>) => {
        const container = firstContainer(at(job, 'properties'));
        if (container !== undefined) container.probes = [];
      },
      "its container has probes, which this tool doesn't copy",
    ],
    [
      'another command',
      (job: Record<string, unknown>) => {
        const container = firstContainer(at(job, 'properties'));
        if (container !== undefined) container.args = ['--request', '/mnt/secrets/operator-request', '--name', 'x'];
      },
      'it must run node apps/operator/src/main.ts --request /mnt/secrets/operator-request',
    ],
    [
      'its request shown',
      (job: Record<string, unknown>) => {
        at(job, 'properties', 'configuration').secrets = [...REFERENCES, { name: REQUEST_SECRET, value: NO_REQUEST }];
      },
      'it must hold operator-request once, nothing of it shown',
    ],
    [
      'its request twice',
      (job: Record<string, unknown>) => {
        at(job, 'properties', 'configuration').secrets = [
          ...REFERENCES,
          { name: REQUEST_SECRET },
          { name: REQUEST_SECRET },
        ];
      },
      'it must hold operator-request once, nothing of it shown',
    ],
    [
      'no request',
      (job: Record<string, unknown>) => {
        at(job, 'properties', 'configuration').secrets = [...REFERENCES];
      },
      'it must hold operator-request once, nothing of it shown',
    ],
    [
      'a secret that is not a reference to the vault',
      (job: Record<string, unknown>) => {
        at(job, 'properties', 'configuration').secrets = [{ name: 'other' }, { name: REQUEST_SECRET }];
      },
      NOT_A_REFERENCE,
    ],
    [
      'a reference with more to it',
      (job: Record<string, unknown>) => {
        at(job, 'properties', 'configuration').secrets = [{ ...REFERENCES[0], value: 'x' }, { name: REQUEST_SECRET }];
      },
      NOT_A_REFERENCE,
    ],
    [
      // Sent back as read, it would break the reference.
      'a reference without its identity',
      (job: Record<string, unknown>) => {
        const [first] = REFERENCES;
        at(job, 'properties', 'configuration').secrets = [
          { name: first?.name, keyVaultUrl: first?.keyVaultUrl },
          { name: REQUEST_SECRET },
        ];
      },
      NOT_A_REFERENCE,
    ],
    [
      'a reference without its name',
      (job: Record<string, unknown>) => {
        const [first] = REFERENCES;
        at(job, 'properties', 'configuration').secrets = [
          { keyVaultUrl: first?.keyVaultUrl, identity: first?.identity },
          { name: REQUEST_SECRET },
        ];
      },
      NOT_A_REFERENCE,
    ],
    [
      'secrets that are not a list',
      (job: Record<string, unknown>) => {
        at(job, 'properties', 'configuration').secrets = {};
      },
      'its secrets are not a list',
    ],
    [
      'no time limit',
      (job: Record<string, unknown>) => {
        at(job, 'properties', 'configuration').replicaTimeout = '300';
      },
      'it has no time limit',
    ],
    [
      'no time of its last change',
      (job: Record<string, unknown>) => {
        job.systemData = {};
      },
      "Azure gave no time of its last change, so one of ours can't be told apart",
    ],
  ] as const)('refuses a job with %s, writing nothing', async (_what, change, why) => {
    const done = await run(create, { job: change });

    expect(done.error).toMatchObject({
      message: `jobs/job-agentx-stg-operator isn't the operator's job this tool knows (${why}): deploy it by hand.`,
    });
    expect(done.az.sent).toEqual([]);
  });

  it('refuses a time limit that is not a whole number of seconds above nothing', async () => {
    for (const limit of [0, -1, 1.5]) {
      const done = await run(create, {
        job: (job) => {
          at(job, 'properties', 'configuration').replicaTimeout = limit;
        },
      });
      expect(messageOf(done.error)).toContain('(it has no time limit)');
    }
  });

  it('puts [] back when Azure refuses the request, and the refusal stands, quoting nothing sent', async () => {
    const done = await run(create, { patchStatus: [1] });

    expect(done.error).toMatchObject({
      message:
        "Azure refused writing the request and bringing the job to the API's build (Bad Request, InvalidParameter). Its message isn't shown, since it can quote what was sent: the resource group's activity log has it.",
    });
    expect(messageOf(done.error)).not.toContain('Zephyrine');
    expect(done.az.sent).toHaveLength(2);
    expect(done.az.request).toBe(NO_REQUEST);
    expect(done.az.sequence).not.toContain('containerapp job start');
    expect(done.said.at(-1)).toBe(tryAgain(idSaid(done.said)));
  });

  it('puts [] back when the start is refused, and the refusal stands', async () => {
    const done = await run(create, { startStatus: 1 });

    expect(done.error).toBeInstanceOf(Error);
    expect(done.az.request).toBe(NO_REQUEST);
    expect(done.said.slice(-2)).toEqual([
      'Put [] back on job-agentx-stg-operator: its next run holds no request until one is written.',
      tryAgain(idSaid(done.said)),
    ]);
  });

  it('says what holds the request, and what takes it off, when putting [] back fails after another failure', async () => {
    const done = await run(create, { startStatus: 1, patchStatus: [0, 1] });

    expect(messageOf(done.error)).toMatch(/^az containerapp job start /);
    expect(done.said.slice(-2)).toEqual([
      `Putting [] back failed too: Azure refused putting [] back (Bad Request, InvalidParameter). Its message isn't shown, since it can quote what was sent: the resource group's activity log has it. ${mayStillHold(idSaid(done.said))}`,
      tryAgain(idSaid(done.said)),
    ]);
  });

  it('says what the run did before saying [] could not be put back, and then ends 1', async () => {
    const done = await run(create, { patchStatus: [0, 1] });
    const id = idHeld(done.az);

    expect(done.error).toBeUndefined();
    expect(done.status).toBe(1);
    expect(done.said.slice(-2)).toEqual([
      `Created the organisation ${id}.`,
      `Putting [] back failed: Azure refused putting [] back (Bad Request, InvalidParameter). Its message isn't shown, since it can quote what was sent: the resource group's activity log has it. ${mayStillHold(id)}`,
    ]);
  });

  it('stops when Azure ends a change as failed or cancelled, and puts [] back', async () => {
    for (const settles of ['Failed', 'Canceled'] as const) {
      const done = await run(create, { settles: [settles] });
      expect(done.error).toMatchObject({
        message: `Azure's change to job-agentx-stg-operator for writing the request and bringing the job to the API's build ended ${settles}.`,
      });
      expect(done.az.sequence).not.toContain('containerapp job start');
      expect(done.az.request).toBe(NO_REQUEST);
    }
  });

  it("gives a change that never settles 10 minutes, then says the request can't come off while it is still going", async () => {
    const done = await run(create, { settles: ['never'] });
    const id = idSaid(done.said);

    expect(done.error).toMatchObject({
      message:
        "Azure hadn't settled writing the request and bringing the job to the API's build on job-agentx-stg-operator after 10 minutes (InProgress).",
    });
    expect(done.said.slice(-2)).toEqual([
      `Putting [] back failed too: job-agentx-stg-operator was still taking a change after 10 minutes, so nothing more was sent. ${mayStillHold(id)}`,
      tryAgain(id),
    ]);
    // No PATCH made while the first was still going: 10 minutes for it to settle, then 10 for the job to be free.
    expect(done.az.sent).toHaveLength(1);
    expect(done.slept).toEqual(Array.from({ length: 80 }, () => 15_000));
  });

  it('says a change not yet taken when Azure still shows the job as it was, at exactly 10 minutes', async () => {
    const done = await run(create, { lag: 1_000 });

    expect(messageOf(done.error)).toMatch(/after 10 minutes \(Succeeded, not yet taken\)\.$/);
    // A reading every 15 s until the 10 minutes are up, and none past them: then [] can't go back, the request still going.
    expect(done.slept).toEqual(Array.from({ length: 40 }, () => 15_000));
    expect(done.az.sequence.filter((call) => call === 'get job')).toHaveLength(1 + 41 + 1);
    expect(done.said.at(-2)).toMatch(
      /^Putting \[\] back failed too: Azure refused putting \[\] back \(Conflict, ContainerAppOperationInProgress\)\. /,
    );
  });

  it("says how to find out and finish when the run ended but its log can't be read", async () => {
    const done = await run(create, { logRefused: true });

    expect(messageOf(done.error)).toMatch(/^az rest --method post /);
    expect(done.az.request).toBe(NO_REQUEST);
    expect(done.said.at(-1)).toBe(tryAgain(idHeld(done.az)));
  });
});

/** One run of the restore drill's check, with a clock that moves only when it sleeps. */
async function check(script: Script) {
  const az = new FakeAzure(script);
  const lines: string[] = [];
  let now = START.getTime();
  const status = await restoreCheck({
    az,
    say: (line) => lines.push(line),
    now: () => new Date(now),
    sleep: (ms) => {
      now += ms;
      return Promise.resolve();
    },
  });
  return { status, az, said: lines };
}

describe("S78 the restore drill's check", () => {
  it('writes its one word, runs it, puts [] back and says the copy holds', async () => {
    const done = await check({ ending: 'copy-holds' });

    expect(done.status).toBe(0);
    expect(done.az.heldAtStart).toBe(restoreCheckRequest());
    expect(done.az.request).toBe(NO_REQUEST);
    expect(done.said[1]).toBe("Checking the drill's copy against the live server, read-only.");
    expect(done.said.at(-1)).toBe(
      'The copy holds: all 4 chains on it checked whole, and each leads to the live one (3 organisations on the copy, 1 made since; the platform chain at 9 on the copy, 11 live).',
    );
  });

  it('says each problem when the copy does not hold, and ends 1', async () => {
    const done = await check({ ending: 'copy-broken', states: ['Failed'] });
    expect(done.status).toBe(1);
    expect(done.az.request).toBe(NO_REQUEST);
    expect(done.said.at(-1)).toBe(
      "The copy does not hold: platform on the live server, from the copy's head: anchor at 7; and 2 more.",
    );
  });

  it('says a refusal read nothing, and ends 1', async () => {
    const done = await check({ ending: 'check-refused', states: ['Failed'] });
    expect(done.status).toBe(1);
    expect(done.said.at(-1)).toBe(
      'The check was refused, and read nothing: a connection is not read-only, so nothing was read.',
    );
  });

  it("says so when none of the command's lines arrived, whether the run succeeded or not", async () => {
    expect((await check({ ending: 'silent' })).said.at(-1)).toBe(
      "The run succeeded, but its lines don't say what it found: they may not all have arrived. Run the same command again: it only reads.",
    );
    const stopped = await check({ ending: 'silent', states: ['Failed'] });
    expect(stopped.status).toBe(1);
    expect(stopped.said.at(-1)).toBe(
      "The check didn't finish: read the lines above (is the drill's copy up, in the same subnet and private zone?). Run it again once it is: it only reads.",
    );
  });

  it('takes no words after its own', async () => {
    const lines: string[] = [];
    await expect(
      main(
        ['restore-check', '--id', EARLIER_ID],
        (line) => lines.push(line),
        () => new FakeAzure({}),
      ),
    ).resolves.toBe(2);
    expect(lines).toEqual([`say restore-check, and nothing else\n${USAGE}`]);
  });
});

describe('main', () => {
  it('says how to use it, and ends 2, when asked something else', async () => {
    const lines: string[] = [];
    await expect(
      main(
        ['create-organization'],
        (line) => lines.push(line),
        () => new FakeAzure({}),
      ),
    ).resolves.toBe(2);
    expect(lines).toEqual([
      `say create-organization --name <name> [--id <ID>], the name as one argument, and nothing else\n${USAGE}`,
    ]);
  });

  it('reads invite-first-admin as its own command, saying how to use it, and ends 2, when asked it wrongly (B4-6b)', async () => {
    const lines: string[] = [];
    await expect(
      main(
        ['invite-first-admin', '--org'],
        (line) => lines.push(line),
        () => new FakeAzure({}),
      ),
    ).resolves.toBe(2);
    expect(lines).toEqual([
      `say invite-first-admin --org <organisation ID> --email <address> [--id <ID>], and nothing else
${USAGE}`,
    ]);
  });

  it('says what stopped it, and ends 1', async () => {
    const lines: string[] = [];
    await expect(
      main(
        create,
        (line) => lines.push(line),
        () => new FakeAzure({ state: 'Failed' }),
      ),
    ).resolves.toBe(1);
    expect(lines.at(-1)).toBe(
      'job-agentx-stg-operator is Failed from an earlier change, so nothing was written: look at it first.',
    );
  });
});

describe('the runner and the deployment agree', () => {
  it("names the operator's job, its container, its command and the request it holds as deployed", () => {
    const created = inCopy((dir) => environmentSnapshot(dir, 'staging').together).predictedResources;
    const job = created.find((resource) => resource.name === jobName('operator'));
    expect(job?.type).toBe('Microsoft.App/jobs');
    expect(`jobs/${String(job?.name)}`).toBe(OPERATOR_JOB.path);
    const container = firstContainer(job?.properties);
    expect(container?.name).toBe(OPERATOR_JOB.container);
    expect([...(container?.command as string[]), ...(container?.args as string[])]).toEqual([
      'node',
      'apps/operator/src/main.ts',
      '--request',
      `/mnt/secrets/${REQUEST_SECRET}`,
    ]);
    expect(at(job?.properties, 'configuration').secrets).toContainEqual({ name: REQUEST_SECRET, value: NO_REQUEST });
    // The restore drill's copy (S78): the name the playbook restores to, beside the live server's.
    const settings = container?.env as { name: string; value?: string }[];
    const value = (name: string): string | undefined => settings.find((setting) => setting.name === name)?.value;
    expect(value('AGENTX_DB_DRILL_HOST')).toBe('psql-agentx-stg-drill.postgres.database.azure.com');
    expect(value('AGENTX_DB_HOST')).toMatch(/^psql-agentx-stg-[a-z0-9]{6}\.postgres\.database\.azure\.com$/);
  });

  it("names the chain repair's job, its container, its command and the request it holds as deployed (4D2e E10)", () => {
    const created = inCopy((dir) => environmentSnapshot(dir, 'staging').together).predictedResources;
    const job = created.find((resource) => resource.name === jobName('chain-restore'));
    expect(`jobs/${String(job?.name)}`).toBe(RESTORE_JOB.path);
    const container = firstContainer(job?.properties);
    expect(container?.name).toBe(RESTORE_JOB.container);
    expect([...(container?.command as string[]), ...(container?.args as string[])]).toEqual([
      'node',
      'apps/operator/src/chain-restore-main.ts',
      '--request',
      `/mnt/secrets/${RESTORE_REQUEST_SECRET}`,
    ]);
    expect(at(job?.properties, 'configuration').secrets).toContainEqual({
      name: RESTORE_REQUEST_SECRET,
      value: NO_REQUEST,
    });
    const settings = container?.env as { name: string; value?: string }[];
    expect(settings.find((entry) => entry.name === 'AGENTX_DB_USER')?.value).toBe('agentx_owner');
  });
});

/** A value deep in an answer, as an object a test can change. */
function at(value: unknown, ...keys: readonly string[]): Record<string, unknown> {
  let found: unknown = value;
  for (const key of keys) found = (found as Record<string, unknown> | undefined)?.[key];
  return (found ?? {}) as Record<string, unknown>;
}

/** The first container in an answer's properties, as an object a test can change. */
function firstContainer(properties: unknown): Record<string, unknown> | undefined {
  const containers = at(properties, 'template').containers;
  return Array.isArray(containers) ? (containers[0] as Record<string, unknown> | undefined) : undefined;
}

/** What a failure said, or that there was none. */
const messageOf = (error: unknown): string =>
  error instanceof Error ? error.message : `no error but ${String(error)}`;

describe('parseFirstAdmin (B4-6b)', () => {
  const ORG_ID = '0199a1b2-c3d4-7e5f-8a6b-00000000000a';
  const invite = ['invite-first-admin', '--org', ORG_ID, '--email', 'Sara.Khan@Example.test'];

  it('reads the organisation and the address, in lower case, and an earlier ID when given', () => {
    expect(parseFirstAdmin(invite)).toEqual({ orgId: ORG_ID, email: 'sara.khan@example.test', id: undefined });
    expect(parseFirstAdmin([...invite, '--id', EARLIER_ID])).toMatchObject({ id: EARLIER_ID });
  });

  it('refuses anything else, never repeating the address', () => {
    const shape = 'say invite-first-admin --org <organisation ID> --email <address> [--id <ID>], and nothing else';
    for (const [argv, message] of [
      [['invite-first-admin', '--org', ORG_ID], shape],
      [['invite-first-admin', '--email', 'a@b.test', '--org', ORG_ID], shape],
      [[...invite, '--id'], shape],
      [[...invite, '--id', EARLIER_ID, 'more'], shape],
      [
        ['invite-first-admin', '--org', ORG_ID.toUpperCase(), '--email', 'a@b.test'],
        "--org takes the organisation's ID: a UUIDv7, in lower case",
      ],
      [[...invite, '--id', 'not-an-id'], '--id takes the ID an earlier run gave: a UUIDv7, in lower case'],
      [
        ['invite-first-admin', '--org', ORG_ID, '--email', 'not an address'],
        "--email takes the address to invite, and this isn't one",
      ],
    ] as const) {
      expect(() => parseFirstAdmin(argv)).toThrow(new UsageError(message));
    }
  });
});

describe('inviting a first admin (B4-6b)', () => {
  const ORG_ID = '0199a1b2-c3d4-7e5f-8a6b-00000000000a';
  const ADDRESS = 'sara.khan@example.test';

  async function invite(script: Script = {}, id?: string) {
    const az = new FakeAzure({ ending: 'invited', ...script });
    const lines: string[] = [];
    let now = START.getTime();
    const status = await inviteFirstAdmin(
      { orgId: ORG_ID, email: ADDRESS, id },
      {
        az,
        say: (line) => lines.push(line),
        now: () => new Date(now),
        sleep: (ms) => {
          now += ms;
          return Promise.resolve();
        },
      },
    ).then(
      (value) => ({ value, error: undefined }),
      (error: unknown) => ({ value: undefined, error }),
    );
    const words = JSON.parse(az.heldAtStart ?? '[]') as string[];
    return { status: status.value, error: status.error, az, said: lines, words };
  }

  it('sends only the token’s hash, then shows the link once the run says the invitation exists', async () => {
    const done = await invite();

    expect(done.error).toBeUndefined();
    expect(done.status).toBe(0);
    const [command, , orgId, , email, , id, , hash] = done.words;
    expect([command, orgId, email]).toEqual(['invite-first-admin', ORG_ID, ADDRESS]);
    expect(id).toMatch(UUID_V7);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(done.az.request).toBe(NO_REQUEST);
    const last = done.said.at(-1) ?? '';
    const token = /#token=([A-Za-z0-9_-]{43})$/m.exec(last)?.[1] ?? '';
    expect(last).toContain(`Invited the first admin of ${ORG_ID} (invitation ${id}).`);
    expect(last).toContain(`${ORIGIN}/invitations/accept#token=`);
    expect(last).toMatch(/\nTell them to register a passkey as their first second factor/);
    // The token the link carries is the one whose hash was sent, and it was said nowhere else, nor sent.
    expect(createHash('sha256').update(token, 'ascii').digest('hex')).toBe(hash);
    expect(done.said.slice(0, -1).join('\n')).not.toContain(token);
    expect(JSON.stringify(done.az.sent)).not.toContain(token);
  });

  it('shows no link for a request done before, saying how to get a new one', async () => {
    const done = await invite({ ending: 'invited-done-before' }, EARLIER_ID);

    expect(done.status).toBe(0);
    expect(done.words[6]).toBe(EARLIER_ID);
    expect(done.said.at(-1)).toBe(
      `Already done: the invitation ${EARLIER_ID} exists from an earlier run of this request, and nothing changed. Its link was shown by that run alone. If it was lost, run the command again without --id: a new invitation, with a new link.`,
    );
    expect(done.said.join('\n')).not.toContain('#token=');
  });

  it('says what the operator’s command refused, showing no link', async () => {
    const done = await invite({ ending: 'invite-refused' });

    expect(done.status).toBe(1);
    expect(done.said.at(-1)).toBe(
      "The operator's command refused it, and nothing changed: the organisation has members: its admins invite, not the operator.",
    );
    expect(done.said.join('\n')).not.toContain('#token=');
  });

  it.each(['invited-other', 'silent'] as const)(
    'shows no link for a run whose lines don’t say this invitation was made (%s)',
    async (ending) => {
      const done = await invite({ ending });

      expect(done.status).toBe(1);
      expect(done.said.join('\n')).not.toContain('#token=');
      expect(done.said.at(-1)).toContain(`don't show the invitation ${String(done.words[6])} made`);
    },
  );

  it.each([
    'https://app.example.test:8443',
    'https://App.example.test',
    'https://app.example.test/',
    'http://app.example.test',
  ])('writes nothing for an origin it can’t make a link with: %s', async (origin) => {
    const done = await invite({ origin });

    expect(done.error).toEqual(
      new Error('The API holds no https AGENTX_PUBLIC_ORIGIN, so no link could be made: nothing was written.'),
    );
    expect(done.az.sent).toEqual([]);
  });

  it('writes nothing when the API holds no public origin to make the link with', async () => {
    const done = await invite({ noOrigin: true });

    expect(done.error).toEqual(
      new Error('The API holds no https AGENTX_PUBLIC_ORIGIN, so no link could be made: nothing was written.'),
    );
    expect(done.az.sent).toEqual([]);
  });
});

describe('an audit export for a case (E10c)', () => {
  const FROM = '2026-10-01T00:00:00Z';
  const TO = '2026-10-18T00:00:00Z';
  /** A case reference no test line repeats in a problem. */
  const CASE = 'DISPUTE-2026/0042';
  const asked = ['audit-export', '--org', EXPORT_ORG, '--from', FROM, '--to', TO, '--reason', CASE];

  async function exportRun(script: Script = {}, id?: string) {
    const az = new FakeAzure({ ending: 'exported', ...script });
    const lines: string[] = [];
    let now = START.getTime();
    const status = await auditExport(
      { orgId: EXPORT_ORG, from: FROM, to: TO, caseRef: CASE, id },
      {
        az,
        say: (line) => lines.push(line),
        now: () => new Date(now),
        sleep: (ms) => {
          now += ms;
          return Promise.resolve();
        },
      },
    );
    const words = JSON.parse(az.heldAtStart ?? '[]') as string[];
    return { status, az, said: lines, id: String(words[10]), words };
  }

  it('reads the organisation, the range, the case, and an earlier ID when one is given', () => {
    expect(parseAuditExport(asked)).toEqual({ orgId: EXPORT_ORG, from: FROM, to: TO, caseRef: CASE, id: undefined });
    expect(parseAuditExport([...asked, '--id', EARLIER_ID]).id).toBe(EARLIER_ID);
  });

  it("refuses what the operator's command would, before writing anything, never repeating the case", () => {
    const refused = (argv: readonly string[]): string => {
      try {
        parseAuditExport(argv);
      } catch (error) {
        expect(error).toBeInstanceOf(UsageError);
        return (error as Error).message;
      }
      return 'read';
    };
    const shape =
      'say audit-export --org <organisation ID> --from <time> --to <time> --reason <case reference> [--id <ID>], and nothing else';
    for (const argv of [
      asked.slice(0, -1),
      [...asked, '--id'],
      [...asked, '--id', EARLIER_ID, 'more'],
      asked.with(3, '--since'),
      asked.with(7, '--case'),
    ]) {
      expect(refused(argv)).toBe(shape);
    }
    expect(refused([...asked, '--id', 'not-an-id'])).toBe(
      '--id takes the ID an earlier run gave: a UUIDv7, in lower case',
    );
    expect(refused(asked.with(2, 'ORG'))).toBe("the organisation's ID must be a UUIDv7, in lower case");
    expect(refused(asked.with(4, '2026-02-30T00:00:00Z'))).toBe(
      '--from and --to must each be a UTC time, such as 2026-10-01T00:00:00Z',
    );
    expect(refused(asked.with(6, FROM))).toBe('the range starts before it ends, 366 days at most');
    expect(refused(asked.with(6, '2027-10-03T00:00:00Z'))).toBe('the range starts before it ends, 366 days at most');
    const badCase = 'a case with spaces';
    const said = refused(asked.with(8, badCase));
    expect(said).toBe(
      'the case reference must be 3 to 64 letters, digits and . _ / -, starting with a letter or digit',
    );
    expect(said).not.toContain(badCase);
  });

  it('reads an activity log export as an audit log one, refusing the one for the other', () => {
    const activity = asked.with(0, 'activity-export');

    expect(parseAuditExport(activity, 'activity-export')).toEqual({
      orgId: EXPORT_ORG,
      from: FROM,
      to: TO,
      caseRef: CASE,
      id: undefined,
    });
    expect(() => parseAuditExport(activity)).toThrow(UsageError);
  });

  it('runs an activity log export, saying the requests written to its own file', async () => {
    const az = new FakeAzure({ ending: 'activity-exported' });
    const lines: string[] = [];
    let now = START.getTime();
    const status = await auditExport(
      { orgId: EXPORT_ORG, from: FROM, to: TO, caseRef: CASE, id: EARLIER_ID },
      {
        az,
        say: (line) => lines.push(line),
        now: () => new Date(now),
        sleep: (ms) => {
          now += ms;
          return Promise.resolve();
        },
      },
      'activity-export',
    );

    expect(status).toBe(0);
    expect(az.heldAtStart).toBe(activityExportRequest(EXPORT_ORG, FROM, TO, CASE, EARLIER_ID));
    expect(lines.at(-1)).toBe(
      `Exported 7 requests for the case to the store as ${EXPORT_ORG}/activity-${EARLIER_ID}.ndjson (512 bytes, SHA-256 ${'cd'.repeat(32)}). It is recorded on both chains, and the organisation's admins were told.`,
    );
  });

  it("writes the operator's request, runs it, puts [] back and says the file written, its size and hash", async () => {
    const done = await exportRun();

    expect(done.status).toBe(0);
    expect(done.id).toMatch(UUID_V7);
    expect(done.az.heldAtStart).toBe(auditExportRequest(EXPORT_ORG, FROM, TO, CASE, done.id));
    expect(done.az.request).toBe(NO_REQUEST);
    expect(done.said).toContain(
      `The export's ID is ${done.id}. If this run's end is unclear, run the same command again with --id ${done.id}: it records nothing twice, and it takes the request off the job at its end.`,
    );
    expect(done.said.at(-1)).toBe(
      `Exported 42 events for the case to the store as ${EXPORT_ORG}/${done.id}.ndjson (9001 bytes, SHA-256 ${'ab'.repeat(32)}). It is recorded on both chains, and the organisation's admins were told.`,
    );
  });

  it('writes the ID given for a retry, and calls a file there already done', async () => {
    const done = await exportRun({ ending: 'exported-there-already' }, EARLIER_ID);

    expect(done.status).toBe(0);
    expect(done.id).toBe(EARLIER_ID);
    expect(done.said.at(-1)).toBe(
      `Already done: ${EXPORT_ORG}/${EARLIER_ID}.ndjson is in the store from an earlier run of this export, and nothing was written again.`,
    );
  });

  it('says an export recorded but not written, and how the same ID finishes it', async () => {
    const done = await exportRun({ ending: 'export-unwritten', states: ['Failed'] });

    expect(done.status).toBe(1);
    expect(done.said.at(-1)).toBe(
      `The export ${done.id} is recorded on both chains and the organisation's admins were told, but its file wasn't written: the blob service answered 503 (ServerBusy). Run the same command again with --id ${done.id}: it records nothing twice, and writes the file once.`,
    );
  });

  it('says a refusal, a job with no store, and a run that found no request, each recording nothing', async () => {
    const refused = await exportRun({ ending: 'export-refused', states: ['Failed'] });
    expect(refused.status).toBe(1);
    expect(refused.said.at(-1)).toBe(
      "The operator's command refused it, and nothing was recorded: the organisation isn't in the directory.",
    );
    const storeless = await exportRun({ ending: 'no-store', states: ['Failed'] });
    expect(storeless.status).toBe(1);
    expect(storeless.said.at(-1)).toBe(
      `The job has no store for an export set, so nothing was recorded: deploy the apps (deploy.ts apps), then run the same command again with --id ${storeless.id}.`,
    );
    const empty = await exportRun({ ending: 'no-request', states: ['Failed'] });
    expect(empty.status).toBe(1);
    expect(empty.said.at(-1)).toBe(
      `The run found no request, so nothing changed: Azure hadn't put it in place when the run started. Run the same command again with --id ${empty.id}.`,
    );
  });

  it('never takes a line about another export for this one, nor a run whose lines say nothing', async () => {
    for (const ending of ['exported-other', 'silent'] as const) {
      const done = await exportRun({ ending });
      expect({ ending, status: done.status }).toEqual({ ending, status: 1 });
      expect(done.said.at(-1)).toBe(
        `The run succeeded, but its lines don't show the export ${done.id} written: they may not all have arrived, or another request ran in this one's place. Run the same command again with --id ${done.id}, which records nothing twice.`,
      );
    }
    const stopped = await exportRun({ ending: 'failed', states: ['Failed'] });
    expect(stopped.status).toBe(1);
    expect(stopped.said.at(-1)).toBe(
      `The export may not have been recorded or written: read the lines above. If they leave it unclear, run the same command again with --id ${stopped.id}, which records nothing twice.`,
    );
  });

  it('is read by main as its own command, saying how to use it, and ending 2, when asked it wrongly', async () => {
    const lines: string[] = [];
    await expect(
      main(
        ['audit-export', '--org', EXPORT_ORG],
        (line) => lines.push(line),
        () => new FakeAzure({}),
      ),
    ).resolves.toBe(2);
    expect(lines).toEqual([
      `say audit-export --org <organisation ID> --from <time> --to <time> --reason <case reference> [--id <ID>], and nothing else\n${USAGE}`,
    ]);
  });
});

describe('a pause or resume of every hand-off to the bank (Phase 4 B1, SEC-OPS-03)', () => {
  /** A reason no test line repeats in a problem. */
  const REASON = 'INC-2026/0042';
  const resume = ['handoff-resume', '--reason', REASON];

  async function handoffRun(script: Script = {}, request: Partial<HandoffArguments> = {}) {
    const az = new FakeAzure({ ending: 'resumed', ...script });
    const lines: string[] = [];
    let now = START.getTime();
    const status = await handoffChange(
      { command: 'handoff-resume', reason: REASON, id: undefined, ...request },
      {
        az,
        say: (line) => lines.push(line),
        now: () => new Date(now),
        sleep: (ms) => {
          now += ms;
          return Promise.resolve();
        },
      },
    );
    const words = JSON.parse(az.heldAtStart ?? '[]') as string[];
    return { status, az, said: lines, id: String(words[4]) };
  }

  it('reads the command, the reason, and an earlier ID when one is given', () => {
    expect(parseHandoff(resume)).toEqual({ command: 'handoff-resume', reason: REASON, id: undefined });
    expect(parseHandoff(['handoff-pause', '--reason', REASON, '--id', EARLIER_ID])).toEqual({
      command: 'handoff-pause',
      reason: REASON,
      id: EARLIER_ID,
    });
  });

  it("refuses what the operator's command would, before writing anything, never repeating the reason", () => {
    const refused = (argv: readonly string[]): string => {
      try {
        parseHandoff(argv);
      } catch (error) {
        expect(error).toBeInstanceOf(UsageError);
        return (error as Error).message;
      }
      return 'read';
    };
    const shape = 'say handoff-resume --reason <case reference> [--id <ID>], and nothing else';
    for (const argv of [
      resume.slice(0, 1),
      resume.with(1, '--case'),
      [...resume, '--id'],
      [...resume, '--id', EARLIER_ID, 'more'],
    ]) {
      expect(refused(argv)).toBe(shape);
    }
    expect(refused([...resume, '--id', 'not-an-id'])).toBe(
      '--id takes the ID an earlier run gave: a UUIDv7, in lower case',
    );
    const badReason = 'a note with spaces';
    const said = refused(resume.with(2, badReason));
    expect(said).toBe(
      'the case reference must be 3 to 64 letters, digits and . _ / -, starting with a letter or digit',
    );
    expect(said).not.toContain(badReason);
    expect(refused(resume.slice(0, 2))).toBe(
      'the case reference must be 3 to 64 letters, digits and . _ / -, starting with a letter or digit',
    );
  });

  it("writes the operator's request, runs it, puts [] back and says it is in force and every organisation told", async () => {
    const done = await handoffRun();

    expect(done.status).toBe(0);
    expect(done.id).toMatch(UUID_V7);
    expect(done.az.heldAtStart).toBe(handoffRequest('handoff-resume', REASON, done.id));
    expect(done.az.request).toBe(NO_REQUEST);
    expect(done.said).toContain(
      `The resume's platform event ID is ${done.id}. If this run's end is unclear, run the same command again with --id ${done.id}: it records nothing twice, tells only the organisations not told yet, and takes the request off the job at its end.`,
    );
    expect(done.said.at(-1)).toBe(
      `Hand-offs to the bank are resumed (platform event ${done.id}); 3 organisations told now, 0 by an earlier run.`,
    );
  });

  it('writes a pause the same way, with the ID given for a retry', async () => {
    const done = await handoffRun({ ending: 'paused-as-born' }, { command: 'handoff-pause', id: EARLIER_ID });

    expect(done.status).toBe(0);
    expect(done.az.heldAtStart).toBe(handoffRequest('handoff-pause', REASON, EARLIER_ID));
    expect(done.said.at(-1)).toBe(
      'Hand-offs to the bank are already paused, as a new environment starts: nothing was recorded, and nobody was told.',
    );
  });

  it('says a retry recorded nothing again and told only those left', async () => {
    const done = await handoffRun({ ending: 'resumed-told-before' }, { id: EARLIER_ID });

    expect(done.status).toBe(0);
    expect(done.said.at(-1)).toBe(
      `Hand-offs to the bank were already resumed by this request (platform event ${EARLIER_ID}), and nothing was recorded again; 1 organisations told now, 2 by an earlier run.`,
    );
  });

  it('says organisations left untold, and how the same ID tells them', async () => {
    const partly = await handoffRun({ ending: 'resumed-partly-told', states: ['Failed'] });
    expect(partly.status).toBe(1);
    expect(partly.said.at(-1)).toBe(
      `Hand-offs to the bank are resumed (platform event ${partly.id}); 2 organisations told now, 0 by an earlier run, but 1 couldn't be told: their lines are above. Run the same command again with --id ${partly.id}: it records nothing twice, and tells only the organisations not told yet.`,
    );
    const untold = await handoffRun({ ending: 'resumed-untold', states: ['Failed'] });
    expect(untold.status).toBe(1);
    expect(untold.said.at(-1)).toBe(
      `Hand-offs to the bank are resumed (platform event ${untold.id}), but the run's lines don't show every organisation told. Run the same command again with --id ${untold.id}: it records nothing twice, and tells only the organisations not told yet.`,
    );
  });

  it("says hand-offs found as asked by another request's change, telling nobody", async () => {
    const done = await handoffRun({ ending: 'resumed-by-another' });

    expect(done.status).toBe(0);
    expect(done.said.at(-1)).toBe(
      `Hand-offs to the bank are already resumed, by the platform event ${OTHER_ID}: nothing was recorded, and nobody was told by this request. That change's own request, run again with its --id, tells any organisation it didn't.`,
    );
  });

  it('says a refusal and a run that found no request, each recording nothing', async () => {
    const refused = await handoffRun({ ending: 'resume-refused', states: ['Failed'] });
    expect(refused.status).toBe(1);
    expect(refused.said.at(-1)).toBe(
      "The operator's command refused it, and nothing was recorded: the hand-off pause's record can't be verified, so nothing was changed.",
    );
    const empty = await handoffRun({ ending: 'no-request', states: ['Failed'] });
    expect(empty.status).toBe(1);
    expect(empty.said.at(-1)).toBe(
      `The run found no request, so nothing changed: Azure hadn't put it in place when the run started. Run the same command again with --id ${empty.id}.`,
    );
  });

  it('never takes a line about another pause for this one, nor a run whose lines say nothing', async () => {
    for (const ending of ['resumed-other', 'silent'] as const) {
      const done = await handoffRun({ ending });
      expect({ ending, status: done.status }).toEqual({ ending, status: 1 });
      expect(done.said.at(-1)).toBe(
        `The run succeeded, but its lines don't show hand-offs resumed by ${done.id}: they may not all have arrived, or another request ran in this one's place. Run the same command again with --id ${done.id}: it records nothing twice, and tells only the organisations not told yet.`,
      );
    }
    const stopped = await handoffRun({ ending: 'failed', states: ['Failed'] });
    expect(stopped.status).toBe(1);
    expect(stopped.said.at(-1)).toBe(
      `Hand-offs may not have been resumed: read the lines above. If they leave it unclear: Run the same command again with --id ${stopped.id}: it records nothing twice, and tells only the organisations not told yet.`,
    );
  });

  it('is read by main as its own command, saying how to use it, and ending 2, when asked it wrongly', async () => {
    const lines: string[] = [];
    await expect(
      main(
        ['handoff-pause', '--id', EARLIER_ID],
        (line) => lines.push(line),
        () => new FakeAzure({}),
      ),
    ).resolves.toBe(2);
    expect(lines).toEqual([`say handoff-pause --reason <case reference> [--id <ID>], and nothing else\n${USAGE}`]);
  });
});

/** One run of the plan's or the repair's command, read as main reads it, with a clock that moves only when it sleeps. */
async function drill(argv: readonly string[], script: Script) {
  const az = new FakeAzure(script);
  const lines: string[] = [];
  let now = START.getTime();
  const steps = {
    az,
    say: (line: string) => lines.push(line),
    now: () => new Date(now),
    sleep: (ms: number) => {
      now += ms;
      return Promise.resolve();
    },
  };
  const run = (): Promise<number> => {
    if (argv[0] === 'chain-restore') return chainRestore(parseRestore(argv), steps);
    if (argv[0] === 'chain-rebase') return chainRebase(parseRebase(argv), steps);
    if (argv[0] === 'state-recovery-plan') return stateRecoveryPlan(parseStatePlan(argv), steps);
    if (argv[0] === 'state-restore') return stateRestore(parseStateRestore(argv), steps);
    return recoveryPlan(parseRecoveryPlan(argv), steps);
  };
  const status = await run().then(
    (value) => value,
    (error: unknown) => {
      lines.push(messageOf(error));
      return 1;
    },
  );
  return { status, az, said: lines };
}

const PLAN_ORG = '0199a1b2-c3d4-7e5f-8a6b-0000000000a1';
const PLAN_ID = '0199a1b2-c3d4-7e5f-8a6b-0000000000a2';
const DIGEST = 'ab'.repeat(32);

describe("4D2e E9 a chain recovery plan, on the operator's job", () => {
  it("writes the plan's request, puts [] back, and says the plan and the repair's command", async () => {
    const done = await drill(['chain-recovery-plan', '--org', PLAN_ORG], { ending: 'planned' });
    expect(done.status).toBe(0);
    const words = JSON.parse(String(done.az.heldAtStart)) as string[];
    expect(done.az.heldAtStart).toBe(chainRecoveryRequest(PLAN_ORG, String(words[4])));
    expect(words).not.toContain('--discard-fork');
    expect(done.az.request).toBe(NO_REQUEST);
    expect(done.said.at(-2)).toBe(
      `Planned ${String(words[4])}: 2 rows to put back, 1 to replace, 0 to remove; the head put back. Nothing was changed. The plan and its rows are in the evidence store as ${PLAN_ORG}/chain-recovery-${String(words[4])}.ndjson.`,
    );
    expect(done.said.at(-1)).toBe(
      `Once read, the repair is: node deploy/azure/operator.ts chain-restore --org ${PLAN_ORG} --plan ${String(words[4])} --digest ${DIGEST}`,
    );
  });

  it("passes --discard-fork through only when given, and says so in the repair's command", async () => {
    const done = await drill(['chain-recovery-plan', '--org', PLAN_ORG, '--discard-fork'], { ending: 'planned' });
    const words = JSON.parse(String(done.az.heldAtStart)) as string[];
    expect(words.at(-1)).toBe('--discard-fork');
    expect(done.said.at(-1)).toMatch(/ --discard-fork$/);
  });

  it('says why a plan was refused, and ends 1', async () => {
    const fork = await drill(['chain-recovery-plan', '--org', PLAN_ORG], {
      ending: 'plan-refused',
      states: ['Failed'],
    });
    expect(fork.status).toBe(1);
    expect(fork.said.at(-1)).toBe(
      'No plan: refused as fork at 4. Nothing was changed; the refusal is kept in the evidence store. Playbook H says what each reason means.',
    );
    const broken = await drill(['chain-recovery-plan', '--org', PLAN_ORG], {
      ending: 'plan-copy-broken',
      states: ['Failed'],
    });
    expect(broken.said.at(-1)).toMatch(/^No plan: refused as copy_broken at 2 \(mac\)\./);
  });

  it('says a refusal, no request found, and lines that never came', async () => {
    const refused = await drill(['chain-recovery-plan', '--org', PLAN_ORG], { ending: 'refused', states: ['Failed'] });
    expect(refused.said.at(-1)).toBe('Refused, and nothing changed: the name starts or ends with a space.');
    const none = await drill(['chain-recovery-plan', '--org', PLAN_ORG], { ending: 'no-request', states: ['Failed'] });
    expect(none.said.at(-1)).toMatch(/^The run found no request, so nothing changed/);
    const silent = await drill(['chain-recovery-plan', '--org', PLAN_ORG], { ending: 'silent' });
    expect(silent.status).toBe(1);
    expect(silent.said.at(-1)).toBe(
      "The run's lines don't say what it did: they may not all have arrived. Read the lines above. Run the same command again: a plan only reads.",
    );
  });

  it.each([
    [['chain-recovery-plan'], 'say chain-recovery-plan --org <organisation ID> [--discard-fork], and nothing else'],
    [
      ['chain-recovery-plan', '--org', PLAN_ORG, '--force'],
      'say chain-recovery-plan --org <organisation ID> [--discard-fork], and nothing else',
    ],
    [
      ['chain-recovery-plan', '--org', PLAN_ORG, '--discard-fork', '--discard-fork'],
      'say chain-recovery-plan --org <organisation ID> [--discard-fork], and nothing else',
    ],
    [['chain-recovery-plan', '--org', 'ORG'], "--org takes the organisation's ID: a UUIDv7, in lower case"],
  ])('refuses %j before anything is sent', async (argv, problem) => {
    const lines: string[] = [];
    const az = new FakeAzure({});
    await expect(
      main(
        argv,
        (line) => lines.push(line),
        () => az,
      ),
    ).resolves.toBe(2);
    expect(lines).toEqual([`${problem}\n${USAGE}`]);
    expect(az.calls).toEqual([]);
  });
});

describe('4D2e E10 a chain repair, on its own job, as the owner', () => {
  const restore = (...more: string[]) => [
    'chain-restore',
    '--org',
    PLAN_ORG,
    '--plan',
    PLAN_ID,
    '--digest',
    DIGEST,
    ...more,
  ];

  it("writes the repair's request onto the chain repair's job, says the owner-login alert first, and the hold stays", async () => {
    const done = await drill(restore(), { restore: true, ending: 'restored' });
    expect(done.status).toBe(0);
    const words = JSON.parse(String(done.az.heldAtStart)) as string[];
    const id = String(words[8]);
    expect(id).toMatch(UUID_V7);
    expect(done.az.heldAtStart).toBe(chainRestoreRequest({ orgId: PLAN_ORG, planId: PLAN_ID, digest: DIGEST, id }));
    expect(done.az.request).toBe(NO_REQUEST);
    expect(done.az.sequence).toContain('patch job');
    const intro = done.said.find((line) => line.startsWith('Repairing '));
    expect(intro).toBe(
      `Repairing ${PLAN_ORG}'s chain from plan ${PLAN_ID}, as repair ${id}. This run logs in as the database's owner, so the "login by the owner role outside a deploy" SEV-1 alert fires for it about 20 to 35 minutes later, by design. Note this run in the incident log.`,
    );
    expect(done.said.at(-2)).toBe(
      `Repaired: 2 rows put back, 1 replaced, 0 removed; the chain checks whole to 9. The records are in the evidence store as ${PLAN_ORG}/chain-restore-${id}-start.ndjson and -outcome.ndjson. The organisation stays on hold: its admin clears it with a step-up once the investigation is recorded.`,
    );
    // The rebase's command, with the repaired head (4D2e E11).
    expect(done.said.at(-1)).toBe(
      `If the anchor check then alarms "anchor" for this chain, the rebase, once its head is checked: node deploy/azure/operator.ts chain-rebase --chain ${PLAN_ORG} --seq 9 --hash ${'cd'.repeat(32)} --reason repaired --evidence <incident reference>`,
    );
    // A repair from before the head's hash was logged says no rebase.
    const old = await drill(restore(), { restore: true, ending: 'restored-old' });
    expect(old.status).toBe(0);
    expect(old.said.at(-1)).toMatch(/^Repaired: 1 rows put back/);
  });

  it('passes --discard-fork and an earlier --id through only when given', async () => {
    const done = await drill(restore('--id', EARLIER_ID, '--discard-fork'), { restore: true, ending: 'restored' });
    expect(done.az.heldAtStart).toBe(
      chainRestoreRequest({ orgId: PLAN_ORG, planId: PLAN_ID, digest: DIGEST, id: EARLIER_ID }, true),
    );
    const plain = await drill(restore('--id', EARLIER_ID), { restore: true, ending: 'restored' });
    expect(JSON.parse(String(plain.az.heldAtStart))).not.toContain('--discard-fork');
  });

  it.each([
    ['restore-plan', 'the plan made now is refused (fork at 4): make a new plan and read why'],
    [
      'restore-stale',
      'the plan made now is not the one asked for: something changed since it was read. Make a new plan',
    ],
    [
      'restore-signing',
      "where the operator's signing starts on the live chain changed after the plan read it: treat it as tampering (playbook B)",
    ],
    ['restore-moved', 'the live chain changed as the repair began: make a new plan'],
    ['restore-unverified', 'the chain as written failed its check (mac at 3), so every write was rolled back'],
    ['restore-unknown', 'something_new'],
  ] as const)('says a %s refusal in plain words, and ends 1', async (ending, why) => {
    const done = await drill(restore('--id', EARLIER_ID), { restore: true, ending, states: ['Failed'] });
    expect(done.status).toBe(1);
    expect(done.said.at(-1)).toBe(
      `Not repaired, and nothing changed: ${why}. The records are in the evidence store as ${PLAN_ORG}/chain-restore-${EARLIER_ID}-start.ndjson and -outcome.ndjson.`,
    );
  });

  it("says a repair that ran before did nothing now, and a refusal, and another repair's lines are not this one's", async () => {
    const before = await drill(restore('--id', EARLIER_ID), {
      restore: true,
      ending: 'restore-done-before',
      states: ['Failed'],
    });
    expect(before.status).toBe(1);
    expect(before.said.at(-1)).toMatch(/^This repair's ID ran before, so nothing was done now/);
    const settings = await drill(restore(), { restore: true, ending: 'restore-settings', states: ['Failed'] });
    expect(settings.said.at(-1)).toBe(
      'Refused, and nothing changed: AGENTX_DB_USER must be agentx_owner: only the owner may repair a chain.',
    );
    const other = await drill(restore('--id', EARLIER_ID), { restore: true, ending: 'restored-other' });
    expect(other.status).toBe(1);
    expect(other.said.at(-1)).toBe(
      `The run's lines don't say what it did: they may not all have arrived. Read the lines above. Run the same command again with --id ${EARLIER_ID}: a repair that ran stops at its first record and does nothing twice.`,
    );
  });

  it("refuses a job that isn't the chain repair's as deployed", async () => {
    const done = await drill(restore(), {
      restore: true,
      job: (answer) => {
        const container = firstContainer(answer.properties);
        if (container !== undefined) container.args = ['--request', '/mnt/secrets/operator-request'];
      },
    });
    expect(done.status).toBe(1);
    expect(done.said.at(-1)).toMatch(
      /^jobs\/job-agentx-stg-chain-restore isn't the chain repair's job this tool knows \(it must run node apps\/operator\/src\/chain-restore-main\.ts --request \/mnt\/secrets\/chain-restore-request\): deploy it by hand\.$/,
    );
  });

  it.each([
    [['chain-restore', '--org', PLAN_ORG], 'shape'],
    [['chain-restore', '--org', PLAN_ORG, '--plan', PLAN_ID, '--digest', DIGEST, '--force'], 'shape'],
    [['chain-restore', '--org', PLAN_ORG, '--plan', PLAN_ID, '--digest', DIGEST, '--id'], 'shape'],
    [
      ['chain-restore', '--org', PLAN_ORG, '--plan', PLAN_ID, '--digest', DIGEST, '--discard-fork', '--id', EARLIER_ID],
      'shape',
    ],
    [['chain-restore', '--org', 'O', '--plan', 'P', '--digest', 'D', '--id', 'I'], 'values'],
  ])('refuses %j before anything is sent', async (argv, kind) => {
    const lines: string[] = [];
    const az = new FakeAzure({ restore: true });
    await expect(
      main(
        argv,
        (line) => lines.push(line),
        () => az,
      ),
    ).resolves.toBe(2);
    expect(az.calls).toEqual([]);
    expect(lines[0]).toBe(
      kind === 'shape'
        ? `say chain-restore --org <organisation ID> --plan <plan ID> --digest <digest> [--id <ID>] [--discard-fork], and nothing else\n${USAGE}`
        : `--org takes the organisation's ID: a UUIDv7, in lower case; --plan takes the plan's ID: a UUIDv7, in lower case; --digest takes the plan's digest: 64 lower-case hex digits; --id takes the ID an earlier run gave: a UUIDv7, in lower case\n${USAGE}`,
    );
  });
});

describe("4D2e E11 a chain's rebase, on the operator's job", () => {
  const rebase = (...more: string[]) => [
    'chain-rebase',
    '--chain',
    PLAN_ORG,
    '--seq',
    '9',
    '--hash',
    HEAD_HASH_HEX,
    '--reason',
    'repaired',
    '--evidence',
    'INC-2026-11',
    ...more,
  ];
  const AGAIN = (id: string) =>
    `Run the same command again with --id ${id}: a rebase is written once, and a run that stopped between its file and its event on the chain finishes the event.`;

  it("writes the rebase's request onto the operator's job, puts [] back, and says the anchor moved", async () => {
    const done = await drill(rebase(), { ending: 'rebased' });
    expect(done.status).toBe(0);
    const words = JSON.parse(String(done.az.heldAtStart)) as string[];
    const id = String(words[12]);
    expect(id).toMatch(UUID_V7);
    expect(done.az.heldAtStart).toBe(
      chainRebaseRequest({
        chain: PLAN_ORG,
        seq: '9',
        hash: HEAD_HASH_HEX,
        reason: 'repaired',
        evidence: 'INC-2026-11',
        id,
      }),
    );
    expect(done.az.request).toBe(NO_REQUEST);
    expect(done.said.find((line) => line.startsWith('Rebasing '))).toBe(
      `Rebasing ${PLAN_ORG}'s chain on to its head at 9, as rebase ${id}, signed with the operator's rebase key. The API trusts that head from then on: name only a head checked after a sanctioned change.`,
    );
    expect(done.said.at(-1)).toBe(
      `Rebased: ${PLAN_ORG}'s chain's anchor moves on from 7 to 9 (head ${HEAD_HASH_HEX}). The rebase ${id} is in the anchors' store and its event on the chain. The API takes it in on its next read of the store: the anchor alarm for this chain stops, and it logs the warning audit.rebased, by design.`,
    );
    // The incident's reference goes in the request alone: never said.
    expect(done.said.join('\n')).not.toContain('INC-2026-11');
  });

  it('passes the platform chain and an earlier --id through, and says a shorter chain', async () => {
    const platform = await drill(
      ['chain-rebase', '--chain', 'platform', ...rebase('--id', EARLIER_ID).slice(3)].map((word) =>
        word === 'repaired' ? 'recovered' : word,
      ),
      { ending: 'rebased-shorter' },
    );
    expect(JSON.parse(String(platform.az.heldAtStart))).toEqual([
      'chain-rebase',
      '--chain',
      'platform',
      '--seq',
      '9',
      '--hash',
      HEAD_HASH_HEX,
      '--reason',
      'recovered',
      '--evidence',
      'INC-2026-11',
      '--id',
      EARLIER_ID,
    ]);
    expect(platform.status).toBe(0);
    expect(platform.said.at(-1)).toMatch(
      /^Rebased: the platform's chain's anchor moves on from 7 to 9 \(head (?:cd){32}\); the chain is 2 events shorter than its old anchor, and those are given up\. /,
    );
  });

  it('says a rebase finished now, already done, or its event still unwritten', async () => {
    // Its event found on the chain already, as another run wrote it: rebased all the same.
    const recordedBefore = await drill(rebase('--id', EARLIER_ID), { ending: 'rebased-already-recorded' });
    expect(recordedBefore.status).toBe(0);
    expect(recordedBefore.said.at(-1)).toMatch(/^Rebased: /);
    const unrecorded = await drill(rebase('--id', EARLIER_ID), { ending: 'rebased-unrecorded', states: ['Failed'] });
    expect(unrecorded.status).toBe(1);
    expect(unrecorded.said.at(-1)).toBe(
      `The rebase ${EARLIER_ID} is in the anchors' store, but its event on the chain wasn't written. ${AGAIN(EARLIER_ID)}`,
    );
    const finished = await drill(rebase('--id', EARLIER_ID), { ending: 'rebase-recorded' });
    expect(finished.status).toBe(0);
    expect(finished.said.at(-1)).toBe(
      `The rebase ${EARLIER_ID} was written by an earlier run; its event on the chain is written now. It is done.`,
    );
    const already = await drill(rebase('--id', EARLIER_ID), { ending: 'rebase-done-already', states: ['Failed'] });
    expect(already.status).toBe(0);
    expect(already.said.at(-1)).toBe(
      `Already done: the rebase ${EARLIER_ID} and its event on the chain were written by an earlier run.`,
    );
    const still = await drill(rebase('--id', EARLIER_ID), { ending: 'rebase-done-unrecorded', states: ['Failed'] });
    expect(still.status).toBe(1);
    expect(still.said.at(-1)).toBe(
      `The rebase ${EARLIER_ID} is in the anchors' store, but its event on the chain still couldn't be written. ${AGAIN(EARLIER_ID)}`,
    );
    const other = await drill(rebase('--id', EARLIER_ID), { ending: 'rebase-done-other', states: ['Failed'] });
    expect(other.status).toBe(1);
    expect(other.said.at(-1)).toBe(
      `A rebase named ${EARLIER_ID} is already in the anchors' store for another chain or another head, or can't be read as one: nothing was done, and the head named isn't rebased. A new rebase needs no --id.`,
    );
  });

  it.each([
    ['rebase-store', "the anchors' store couldn't be read, so nothing was checked: read the lines above"],
    ['rebase-not-needed', 'the chain already meets its anchor (at 12): there is nothing to move on'],
    ['rebase-not-needed-unanchored', 'the chain already meets its anchor: there is nothing to move on'],
    [
      'rebase-broken',
      "the chain fails its own check (mac at 4), and a rebase never blesses a chain the app didn't write: repair it first (chain-recovery-plan, then chain-restore)",
    ],
    [
      'rebase-head-differs',
      "the chain's head is at 11, not the place named: check the head again and ask for that one",
    ],
    ['rebase-unknown', 'something_new'],
  ] as const)('says a %s refusal in plain words, and ends 1', async (ending, why) => {
    const done = await drill(rebase('--id', EARLIER_ID), { ending, states: ['Failed'] });
    expect(done.status).toBe(1);
    expect(done.said.at(-1)).toBe(`Not rebased, and nothing changed: ${why}.`);
  });

  it("says a refusal and an unclear end, and another rebase's lines are not this one's", async () => {
    const refused = await drill(rebase('--id', EARLIER_ID), { ending: 'refused', states: ['Failed'] });
    expect(refused.said.at(-1)).toBe('Refused, and nothing changed: the name starts or ends with a space.');
    const other = await drill(rebase('--id', EARLIER_ID), { ending: 'rebased-other' });
    expect(other.status).toBe(1);
    expect(other.said.at(-1)).toBe(
      `The run's lines don't say what it did: they may not all have arrived. Read the lines above. ${AGAIN(EARLIER_ID)}`,
    );
  });

  const SHAPE =
    'say chain-rebase --chain <platform | organisation ID> --seq <head number> --hash <head hash> --reason <repaired | recovered> --evidence <incident reference> [--id <ID>], and nothing else';
  it.each([
    [['chain-rebase', '--chain', PLAN_ORG], SHAPE],
    [rebase('--force'), SHAPE],
    [rebase('--id'), SHAPE],
    [rebase('--id', EARLIER_ID, '--id', EARLIER_ID), SHAPE],
    [rebase().map((word) => (word === '--seq' ? '--head' : word)), SHAPE],
    [
      [
        'chain-rebase',
        '--chain',
        'PLATFORM',
        '--seq',
        '0',
        '--hash',
        'CD',
        '--reason',
        'fixed',
        '--evidence',
        'x y',
        '--id',
        'I',
      ],
      "--chain takes platform, or the organisation's ID: a UUIDv7, in lower case; --seq takes the checked head's number: a whole number from 1; --hash takes the checked head's hash: 64 lower-case hex digits; --reason takes repaired or recovered; --evidence takes the incident's reference: 3 to 64 letters, digits and . _ / -, starting with a letter or digit; --id takes the ID an earlier run gave: a UUIDv7, in lower case",
    ],
  ])('refuses %j before anything is sent', async (argv, problem) => {
    const lines: string[] = [];
    const az = new FakeAzure({});
    await expect(
      main(
        argv,
        (line) => lines.push(line),
        () => az,
      ),
    ).resolves.toBe(2);
    expect(az.calls).toEqual([]);
    expect(lines).toEqual([`${problem}\n${USAGE}`]);
  });

  it('runs from the command line as the others do', async () => {
    const lines: string[] = [];
    const az = new FakeAzure({ ending: 'rebased' });
    await expect(
      main(
        rebase(),
        (line) => lines.push(line),
        () => az,
      ),
    ).resolves.toBe(0);
    expect(lines.at(-1)).toMatch(/^Rebased: /);
  });
});

describe("PL-29 follow-up: an organisation's authority rows planned and repaired, on the chain repair's job", () => {
  const restore = (...more: string[]) => [
    'state-restore',
    '--org',
    PLAN_ORG,
    '--plan',
    PLAN_ID,
    '--digest',
    DIGEST,
    ...more,
  ];

  it("writes the plan's request onto the chain repair's job, says the owner-login alert, the plan and the repair's command", async () => {
    const done = await drill(['state-recovery-plan', '--org', PLAN_ORG], { restore: true, ending: 'state-planned' });
    expect(done.status).toBe(0);
    const words = JSON.parse(String(done.az.heldAtStart)) as string[];
    const planId = String(words[4]);
    expect(done.az.heldAtStart).toBe(stateRecoveryRequest(PLAN_ORG, planId));
    expect(done.az.request).toBe(NO_REQUEST);
    expect(done.said.find((line) => line.startsWith('Planning '))).toMatch(
      /from the drill's copy, read-only on both servers\. This run logs in as the database's owner/,
    );
    expect(done.said.at(-2)).toBe(
      `Planned ${planId}: 2 records to put back, 1 planted ones to remove, of 40 checked. Nothing was changed. The plan and its rows are in the evidence store as ${PLAN_ORG}/state-recovery-${planId}.ndjson.`,
    );
    expect(done.said.at(-1)).toBe(
      `Once read, the repair is: node deploy/azure/operator.ts state-restore --org ${PLAN_ORG} --plan ${planId} --digest ${DIGEST}`,
    );
  });

  it('says why a plan was refused, where, and ends 1; and a run that says nothing', async () => {
    const newer = await drill(['state-recovery-plan', '--org', PLAN_ORG], {
      restore: true,
      ending: 'state-plan-refused',
      states: ['Failed'],
    });
    expect(newer.status).toBe(1);
    expect(newer.said.at(-1)).toBe(
      `No plan: refused as newer_than_copy on agent ${OTHER_ID}. Nothing was changed; the refusal is kept in the evidence store. Playbook H says what each reason means.`,
    );
    const broken = await drill(['state-recovery-plan', '--org', PLAN_ORG], {
      restore: true,
      ending: 'state-plan-copy-broken',
      states: ['Failed'],
    });
    expect(broken.said.at(-1)).toMatch(/^No plan: refused as chain_broken \(link at 4\)\./);
    const silent = await drill(['state-recovery-plan', '--org', PLAN_ORG], { restore: true, ending: 'silent' });
    expect(silent.said.at(-1)).toMatch(/Run the same command again: a plan only reads\.$/);
  });

  it("writes the repair's request, an earlier --id kept, and says the hold stays", async () => {
    const done = await drill(restore(), { restore: true, ending: 'states-restored' });
    expect(done.status).toBe(0);
    const id = String((JSON.parse(String(done.az.heldAtStart)) as string[])[8]);
    expect(done.az.heldAtStart).toBe(stateRestoreRequest({ orgId: PLAN_ORG, planId: PLAN_ID, digest: DIGEST, id }));
    expect(done.said.find((line) => line.startsWith('Repairing '))).toMatch(
      new RegExp(`^Repairing ${PLAN_ORG}'s records from plan ${PLAN_ID}, as repair ${id}\\. This run logs in as`),
    );
    expect(done.said.at(-1)).toBe(
      `Repaired: 2 records put back, 1 planted ones removed; every record checks whole. The records are in the evidence store as ${PLAN_ORG}/state-restore-${id}-start.ndjson and -outcome.ndjson. The organisation stays on hold: its admin clears it with a step-up once the investigation is recorded.`,
    );
    const again = await drill(restore('--id', EARLIER_ID), { restore: true, ending: 'states-restored' });
    expect(again.az.heldAtStart).toBe(
      stateRestoreRequest({ orgId: PLAN_ORG, planId: PLAN_ID, digest: DIGEST, id: EARLIER_ID }),
    );
  });

  it.each([
    ['state-restore-plan', 'the plan made now is refused (newer_than_copy): make a new plan and read why'],
    [
      'state-restore-stale',
      'the plan made now is not the one asked for: something changed since it was read. Make a new plan',
    ],
    ['state-restore-moved', `agent ${OTHER_ID} changed as the repair began: make a new plan`],
    [
      'state-restore-write',
      'the database refused a write (code 23503), so every write was rolled back: read playbook H',
    ],
    [
      'state-restore-unverified',
      'what was written did not check out (whole), so every write was rolled back: treat it as tampering (playbook B)',
    ],
    ['state-restore-unknown', 'something_new'],
  ] as const)('says a %s refusal in plain words, and ends 1', async (ending, why) => {
    const done = await drill(restore('--id', EARLIER_ID), { restore: true, ending, states: ['Failed'] });
    expect(done.status).toBe(1);
    expect(done.said.at(-1)).toBe(
      `Not repaired, and nothing changed: ${why}. The records are in the evidence store as ${PLAN_ORG}/state-restore-${EARLIER_ID}-start.ndjson and -outcome.ndjson.`,
    );
  });

  it("says a repair that ran before did nothing now, and lines that don't say", async () => {
    const before = await drill(restore('--id', EARLIER_ID), {
      restore: true,
      ending: 'state-restore-done-before',
      states: ['Failed'],
    });
    expect(before.said.at(-1)).toMatch(/^This repair's ID ran before, so nothing was done now/);
    const silent = await drill(restore('--id', EARLIER_ID), { restore: true, ending: 'silent' });
    expect(silent.status).toBe(1);
    expect(silent.said.at(-1)).toMatch(/a repair that ran stops at its first record and does nothing twice\.$/);
  });

  it.each([
    [['state-recovery-plan'], 'say state-recovery-plan --org <organisation ID>, and nothing else'],
    [
      ['state-recovery-plan', '--org', PLAN_ORG, '--discard-fork'],
      'say state-recovery-plan --org <organisation ID>, and nothing else',
    ],
    [['state-recovery-plan', '--org', 'ORG'], "--org takes the organisation's ID: a UUIDv7, in lower case"],
    [
      ['state-restore', '--org', PLAN_ORG, '--plan', PLAN_ID, '--digest', DIGEST, '--discard-fork'],
      'say state-restore --org <organisation ID> --plan <plan ID> --digest <digest> [--id <ID>], and nothing else',
    ],
    [
      ['state-restore', '--org', PLAN_ORG, '--plan', PLAN_ID],
      'say state-restore --org <organisation ID> --plan <plan ID> --digest <digest> [--id <ID>], and nothing else',
    ],
    [
      ['state-restore', '--org', 'O', '--plan', PLAN_ID, '--digest', DIGEST],
      "--org takes the organisation's ID: a UUIDv7, in lower case",
    ],
  ])('refuses %j before anything is sent', async (argv, problem) => {
    const lines: string[] = [];
    const az = new FakeAzure({ restore: true });
    await expect(
      main(
        argv,
        (line) => lines.push(line),
        () => az,
      ),
    ).resolves.toBe(2);
    expect(az.calls).toEqual([]);
    expect(lines).toEqual([`${problem}\n${USAGE}`]);
  });
});
