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

/**
 * Key Vault's built-in roles that reach its data or who may (Microsoft's list of built-in roles, read 19 Nov 2026):
 * each, given above the vault, reaches every secret, key or certificate in it. Its Reader and Contributor, and the
 * rest of Azure's, read or change no secret. Each as a pair, ID first (the secret scanner reads a role's name beside
 * the next line's ID as a key).
 */
const DATA_ROLES: ReadonlyMap<string, string> = new Map([
  [VAULT_READ_ROLE, 'Key Vault Secrets User'],
  ['b86a8fe4-44ce-4948-aee5-eccb2c155cd7', 'Key Vault Secrets Officer'],
  ['00482a5a-887f-4fb3-b363-3b7fe8e74483', 'Key Vault Administrator'],
  ['8b54135c-b56d-4d72-a534-26097cfdc8d8', 'Key Vault Data Access Administrator'],
  ['14b46e9e-c2b7-41b4-b07b-48a6ebf60603', 'Key Vault Crypto Officer'],
  ['12338af0-0e69-4776-bea7-57ae8d297424', 'Key Vault Crypto User'],
  ['e147488a-f6f5-4113-8e2d-b22465e65bf6', 'Key Vault Crypto Service Encryption User'],
  ['08bbd89e-9f13-488c-ac41-acfcb10c90ab', 'Key Vault Crypto Service Release User'],
  ['a4417e6f-fecd-4de8-b567-7b0420556985', 'Key Vault Certificates Officer'],
  ['db79e9a7-68ee-4b58-9aeb-b90e7c24fcba', 'Key Vault Certificate User'],
]);

/** A role assignment's role by its name, where it is one of Key Vault's data roles; undefined otherwise. */
const dataRoleOf = (roleDefinitionId: string): string | undefined =>
  DATA_ROLES.get(roleDefinitionId.toLowerCase().split('/').at(-1) ?? '');

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
  // count in grantLines only where their role reaches the vault's data.
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
 * Each assignment that reaches the vault's data, as a line: "<workload> reads <secret>" for Key Vault Secrets User on
 * one secret given to one of our identities, the form GRANTS takes; anything else at the vault or under it, and any of
 * Key Vault's data roles above it (its resource group or subscription), said as what it is, in names alone.
 */
export function grantLines({ vault, assignments, identities }: LiveGrants): string[] {
  const at = vault.toLowerCase();
  const under = `${at}/`;
  return assignments.flatMap((each) => {
    const scope = each.scope.toLowerCase();
    const who = identities.get(each.principalId) ?? 'an identity not of this deployment';
    const dataRole = dataRoleOf(each.roleDefinitionId);
    // Above the vault: its group or subscription, a scope the vault's ID starts with.
    if (scope !== at && under.startsWith(`${scope}/`)) {
      return dataRole === undefined
        ? []
        : [`${who} holds ${dataRole} over the whole vault, from above it (its resource group or subscription)`];
    }
    if (scope !== at && !scope.startsWith(under)) return [];
    const role = dataRole ?? 'another role';
    if (!scope.startsWith(`${under}secrets/`)) return [`${who} holds ${role} on the whole vault`];
    const secret = each.scope.slice(under.length + 'secrets/'.length);
    return [
      role === DATA_ROLES.get(VAULT_READ_ROLE) && identities.has(each.principalId)
        ? `${who} reads ${secret}`
        : `${who} holds ${role} on ${secret}`,
    ];
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
