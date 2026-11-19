// Who can read the vault's secrets, read from Azure and held to the repository's list (AZ32, 6F1 audit h19).
// secrets.bicep grants each app and job Key Vault Secrets User on each of its own secrets, and the policy holds
// the templates to GRANTS (policy.ts). But a deploy never removes a grant (Azure.md, "The secrets"), and a grant made
// by hand or by another deployment never passes through the templates at all, so nothing so far read what Azure
// holds. This does: every role assignment at the vault or under it, each read as "<workload> reads <secret>" where it
// is one of ours, against GRANTS. One more than the list is a way into a secret nobody decided on, and fails.
//
// Run by CI's infrastructure plan on every merge (infra.ts, as the read-only what-if identity, Reader on the group),
// and by hand: node deploy/azure/grants.ts (signed in with az). Names only: never a principal's ID, the vault's or the
// subscription's, since CI's log is public.
import { ARM, armList, type Az, azJson, realAz, RESOURCE_GROUP, text } from './deploy.ts';
import { GRANTS } from './policy.ts';

/** The one role a grant of ours gives (built in, the same ID in every tenant). */
const VAULT_READ_ROLE = '4633458b-17de-408a-b874-0445c86b69e6';

/** The role assignments API this reads with. */
const ASSIGNMENTS_API = '2022-04-01';

/** Our identities' names: `id-agentx-<short>-<workload>` (names.bicep). */
const OUR_IDENTITY = /^id-agentx-[a-z]+-([a-z-]+)$/;

/** One role assignment as Azure lists it: where, to whom, which role. */
export interface Assignment {
  readonly scope: string;
  readonly principalId: string;
  readonly roleDefinitionId: string;
}

/** What Azure holds that a grant reads: the vault's ID, every assignment that applies under it, our identities. */
export interface LiveGrants {
  readonly vault: string;
  readonly assignments: readonly Assignment[];
  /** Each of our identities' principal ID, to the workload it is (`api`, `migrate`, …). */
  readonly identities: ReadonlyMap<string, string>;
}

/** What Azure holds, read through Resource Manager: the vault, our identities, and the assignments on the vault. */
export function readLiveGrants(az: Az, subscription: string): LiveGrants {
  const vaults = azJson(az, [
    'keyvault',
    'list',
    '--subscription',
    subscription,
    '--resource-group',
    RESOURCE_GROUP,
    '--query',
    '[].id',
  ]);
  const vault = Array.isArray(vaults) && vaults.length === 1 ? text(vaults[0]) : '';
  if (!vault.startsWith('/subscriptions/')) {
    throw new Error(`${RESOURCE_GROUP} must hold one key vault for its grants to be read: nothing was read.`);
  }
  const listed = azJson(az, [
    'identity',
    'list',
    '--subscription',
    subscription,
    '--resource-group',
    RESOURCE_GROUP,
    '--query',
    '[].{name:name, principalId:principalId}',
  ]);
  const identities = new Map<string, string>();
  for (const identity of Array.isArray(listed)
    ? (listed as readonly { name?: unknown; principalId?: unknown }[])
    : []) {
    const workload = OUR_IDENTITY.exec(text(identity.name))?.[1];
    if (workload !== undefined && text(identity.principalId) !== '')
      identities.set(text(identity.principalId), workload);
  }
  // With no filter, Resource Manager lists the assignments at, above and below the scope (Microsoft): those above
  // are dropped by scope in grantLines.
  const assignments = armList(
    { az },
    `${ARM}${vault.slice(1)}/providers/Microsoft.Authorization/roleAssignments?api-version=${ASSIGNMENTS_API}`,
    "the vault's role assignments",
  ).map((item) => {
    const properties = (item as { properties?: Record<string, unknown> }).properties ?? {};
    return {
      scope: text(properties.scope),
      principalId: text(properties.principalId),
      roleDefinitionId: text(properties.roleDefinitionId),
    };
  });
  return { vault, assignments, identities };
}

/**
 * Each assignment at the vault or under it, as a line: "<workload> reads <secret>" for Key Vault Secrets User on one
 * secret given to one of our identities, the form GRANTS takes; anything else said as what it is, in names alone.
 */
export function grantLines({ vault, assignments, identities }: LiveGrants): string[] {
  const under = `${vault.toLowerCase()}/`;
  return assignments
    .filter((each) => each.scope.toLowerCase() === vault.toLowerCase() || each.scope.toLowerCase().startsWith(under))
    .map((each) => {
      const who = identities.get(each.principalId) ?? 'an identity not of this deployment';
      const secret = each.scope.toLowerCase().startsWith(`${under}secrets/`)
        ? each.scope.slice(under.length + 'secrets/'.length)
        : undefined;
      const role = each.roleDefinitionId.toLowerCase().endsWith(`/${VAULT_READ_ROLE}`)
        ? 'Key Vault Secrets User'
        : 'another role';
      if (secret === undefined) return `${who} holds ${role} on the whole vault`;
      return role === 'Key Vault Secrets User' && identities.has(each.principalId)
        ? `${who} reads ${secret}`
        : `${who} holds ${role} on ${secret}`;
    });
}

/** The live lines against GRANTS: each one more than the list (the failure), and each of the list Azure lacks. */
export function grantDrift(
  lines: readonly string[],
  grants: ReadonlySet<string> = GRANTS,
): { readonly extra: string[]; readonly missing: string[] } {
  const live = new Set(lines);
  return {
    extra: [...live].filter((line) => !grants.has(line)).sort(),
    missing: [...grants].filter((grant) => !live.has(grant)).sort(),
  };
}

/** The check, said in plain words: 0 when Azure holds no grant beyond the list, 1 when it does. */
export function checkGrants(az: Az, subscription: string, say: (line: string) => void): number {
  const { extra, missing } = grantDrift(grantLines(readLiveGrants(az, subscription)));
  if (missing.length > 0) {
    say(
      `The vault lacks ${String(missing.length)} grant${missing.length === 1 ? '' : 's'} the repository lists (the next secrets run makes them): ${missing.join('; ')}.`,
    );
  }
  if (extra.length === 0) {
    say("The vault's grants: none beyond the repository's list (GRANTS, policy.ts).");
    return 0;
  }
  say(
    `The vault holds ${String(extra.length)} grant${extra.length === 1 ? '' : 's'} the repository doesn't list: ${extra.join('; ')}.`,
  );
  say(
    'What broke: each is a way into a secret nobody decided on, so this run stops here and nothing is planned. What next: find who made it in the activity log; if it is not ours, treat it as playbook section B; then delete it (portal: the vault or the secret, Access control) and read the grants again (node deploy/azure/grants.ts), or add it to secrets.bicep and GRANTS in a reviewed PR.',
  );
  return 1;
}

if (import.meta.main) {
  const az = realAz();
  const subscription = text((azJson(az, ['account', 'show']) as { id?: unknown }).id);
  process.exitCode = checkGrants(az, subscription, (line) => {
    console.log(line);
  });
}
