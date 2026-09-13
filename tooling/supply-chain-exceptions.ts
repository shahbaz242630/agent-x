/**
 * Every relaxation of the pnpm supply-chain settings (SEC-SC-01), with its
 * reason, owner and expiry (Rule Book §7). The SEC-SC-01 check fails when
 * pnpm-workspace.yaml and this list disagree, or when an entry has expired.
 */
export interface SupplyChainException {
  setting: 'allowBuilds' | 'minimumReleaseAgeExclude' | 'trustPolicyExclude';
  /** The package selector exactly as written in pnpm-workspace.yaml. */
  selector: string;
  reason: string;
  owner: string;
  /** The last day the exception holds, as YYYY-MM-DD. */
  expires: string;
}

export const SUPPLY_CHAIN_EXCEPTIONS: readonly SupplyChainException[] = [];
