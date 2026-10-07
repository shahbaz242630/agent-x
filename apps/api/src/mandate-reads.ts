// The reads the mandates' use cases share (Phase 2 B2–B3): drafting
// (mandate-registry.ts) and accepting (mandate-acceptance.ts) each read a
// mandate, its versions and their source the same way, and answer with the
// mandate as it now stands.
import type { AgentsTables } from '@agentx/core/modules/agents';
import type { SignedStates } from '@agentx/core/modules/audit';
import { type FundingSourcesTables, type SourceRecord, sourceOf } from '@agentx/core/modules/funding-sources';
import {
  type ConsentAllows,
  consentCheck,
  type MandateRecord,
  type MandatesTables,
  type MandateVersionRecord,
  mandateOf,
  mandateVersionOf,
} from '@agentx/core/modules/mandates';
import type { SuppliersTables } from '@agentx/core/modules/suppliers';
import { money } from '@agentx/core/shared-kernel';
import type { DatabaseTransaction } from '@agentx/platform/db';

import { UseCaseRefused, type UseCaseTables } from './use-case-work.ts';

export type MandateTables = UseCaseTables & MandatesTables & AgentsTables & FundingSourcesTables & SuppliersTables;
export type MandateTx = DatabaseTransaction<MandateTables>;

/** The mandates' UseCaseRefused: the only refusal their work answers. */
export class MandateRefused extends UseCaseRefused {}

/** A version as the routes show it: its terms, and how they now stand against the bank consent. */
export interface VersionShown {
  readonly version: MandateVersionRecord;
  readonly consentWarnings: readonly string[];
}

/** A mandate as the routes show it: its signed state, its version in force and its waiting draft. */
export interface MandateView {
  readonly mandate: MandateRecord;
  readonly current: VersionShown | null;
  readonly pending: VersionShown | null;
}

/** What a source's bank consent allows, as the terms are checked against it. */
export const consentOf = ({ controls: { currency, period, maxPaymentMinor, maxPeriodMinor } }: SourceRecord) =>
  ({
    currency,
    maxPayment: money(maxPaymentMinor, currency),
    maxPeriod: money(maxPeriodMinor, currency),
    limitPeriod: period,
  }) satisfies ConsentAllows;

/** The source, read (`share`) and verified: SOURCE_NOT_USABLE for none of the organisation's. */
export async function sourceIn(tx: MandateTx, states: SignedStates, orgId: string, sourceId: string) {
  const read = await sourceOf(tx, states, { orgId, id: sourceId }, 'share');
  if (read.outcome === 'tampered') throw new MandateRefused(503, 'INTEGRITY_FAILED');
  if (read.outcome === 'missing') throw new MandateRefused(409, 'SOURCE_NOT_USABLE');
  return read.source;
}

/** The mandate read (`share` or `change`) and verified: NOT_FOUND, or INTEGRITY_FAILED for one that can't be believed. */
export async function mandateIn(
  tx: MandateTx,
  states: SignedStates,
  orgId: string,
  id: string,
  lock: 'share' | 'change',
) {
  const read = await mandateOf(tx, states, { orgId, id }, lock);
  if (read.outcome === 'tampered') throw new MandateRefused(503, 'INTEGRITY_FAILED');
  if (read.outcome === 'missing') throw new MandateRefused(404, 'NOT_FOUND');
  return read;
}

/** A version of the mandate, read (`share`) and verified: INTEGRITY_FAILED for one that can't be believed. */
export async function versionIn(
  tx: MandateTx,
  states: SignedStates,
  orgId: string,
  mandateId: string,
  versionId: string,
): Promise<MandateVersionRecord> {
  const read = await mandateVersionOf(tx, states, { orgId, id: versionId }, mandateId);
  if (read.outcome === 'tampered') throw new MandateRefused(503, 'INTEGRITY_FAILED');
  // 0035's keys hold a mandate's versions to its own.
  if (read.outcome === 'missing') throw new Error(`A mandate names a version not its own: ${mandateId}`);
  return read.version;
}

/** A version of the mandate with how it now stands against its source's consent, whatever its setting. */
async function versionShown(
  tx: MandateTx,
  states: SignedStates,
  orgId: string,
  mandateId: string,
  versionId: string | null,
): Promise<VersionShown | null> {
  if (versionId === null) return null;
  const version = await versionIn(tx, states, orgId, mandateId, versionId);
  const source = await sourceIn(tx, states, orgId, version.fundingSourceId);
  return { version, consentWarnings: consentCheck(version, consentOf(source)).problems };
}

/** The mandate as it now stands, with its version in force and its waiting draft. */
export async function viewIn(
  tx: MandateTx,
  states: SignedStates,
  orgId: string,
  mandateId: string,
): Promise<MandateView> {
  const { mandate } = await mandateIn(tx, states, orgId, mandateId, 'share');
  return {
    mandate,
    current: await versionShown(tx, states, orgId, mandate.id, mandate.currentVersionId),
    pending: await versionShown(tx, states, orgId, mandate.id, mandate.pendingVersionId),
  };
}
