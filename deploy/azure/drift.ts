// What this commit's apps.bicep gives a workload's one container, and how a live
// container differs from it (AZ2c, S188). CI's release identity may write the API
// and the migration job and start the job: a stolen CI sign-in could change the
// job's command, keep our image by digest, and start it, and Azure's activity log
// keeps no request body for that write. A release copies whatever the live
// container holds (release.ts `released`), so it would carry such a change
// forward. So the release first holds each live container to what the commit's
// own templates say, beyond the two things a release changes (the image and
// AGENTX_RELEASE): its command, arguments, settings (names, and plain values; a
// secret by the name it refers to), mounts and size.
//
// The expected container comes from the pinned Bicep's snapshot of
// staging.apps.bicepparam in the real subscription (snapshot.ts), as `apps` would
// deploy it with no load run. Two kinds of value Bicep can't settle offline are
// matched rather than compared:
// - what only the partner's shell gives `apps` (the two hosts, the API's client ID
//   in Zitadel): never in this repository (Rule Book §7), nor in CI. Each is
//   snapshotted as a marker and matched as a host (or an ID), the same everywhere
//   it is used
// - what Azure names at deploy time (`reference(...)` an existing resource's
//   property, `environment()`'s suffixes): each is matched as a host, or a GUID
//   for a client ID, and the same reference must read the same in every setting
//   of both workloads. Any other expression is refused: never guessed at
// No value is ever said: the settings name the domain, and CI's log is public.
import { DEPLOYMENTS, RESOURCE_GROUP } from './deploy.ts';
import { deploymentSnapshot, inCopy } from './snapshot.ts';

/** One setting: a value, or a reference to one of the workload's secrets (never a value in hand). */
export type Setting =
  { readonly name: string; readonly value: string } | { readonly name: string; readonly secretRef: string };

/** A container as a release reads it from Azure (release.ts `Container`, which adds its name and image): the fields compared. */
export interface LiveContainer {
  readonly command: readonly string[];
  readonly args: readonly string[];
  readonly env: readonly Setting[];
  readonly resources: { readonly cpu: number; readonly memory: string };
  readonly volumeMounts: readonly { readonly volumeName: string; readonly mountPath: string }[];
}

/** The settings a release writes itself (release.ts RELEASE_SETTING): its value is never compared. */
const RELEASE_SETTING = 'AGENTX_RELEASE';

/** A DNS name with at least one dot, in lower case, as Azure and the partner's hosts are written. */
const HOST = '[a-z0-9-]+(?:\\.[a-z0-9-]+)+';

/** A GUID, as Azure writes a client ID. */
const GUID_PATTERN = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';

/** One piece of an expected value: text as it must read, or a hole read by its pattern, the same wherever its key is. */
type Part = { readonly text: string } | { readonly key: string; readonly pattern: string };

const UNREADABLE = 'an expression this tool cannot read';

const escaped = (text: string): string => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * The markers the shell's values are snapshotted as, each found again in what
 * Bicep resolves and matched as a hole: a host, or the API's client ID in Zitadel
 * as its config takes it (visible ASCII). Each is a name nothing else in the
 * templates holds. Zitadel's admin e-mail, the shell's other value, is Zitadel's
 * alone: snapshot.ts's stand-in serves.
 */
export const SHELL_MARKERS: Readonly<Record<string, { readonly marker: string; readonly pattern: string }>> = {
  AGENTX_AZURE_APP_HOST: { marker: 'app-host.shell-marker.invalid', pattern: HOST },
  AGENTX_AZURE_AUTH_HOST: { marker: 'auth-host.shell-marker.invalid', pattern: HOST },
  AGENTX_AZURE_API_OIDC_CLIENT_ID: { marker: 'oidc-client-id-shell-marker', pattern: '[!-~]+' },
};

/** A name from Azure as it is printed: anything but letters, digits, `_`, `.` and `-` becomes `?` (no line break can reach the log). */
export const shown = (name: string): string => name.replace(/[^\w.-]/g, '?');

/** One token of an ARM expression. */
type Token =
  | { readonly kind: 'string'; readonly text: string }
  | { readonly kind: 'name'; readonly text: string }
  | { readonly kind: 'number'; readonly text: string }
  | { readonly kind: 'mark'; readonly text: string };

/** An ARM expression's tokens: strings ('' for a quote), names, whole numbers and ( ) , . — anything else is refused. */
function tokens(expression: string): Token[] {
  const found: Token[] = [];
  const pattern = /\s*(?:'((?:[^']|'')*)'|([A-Za-z_]\w*)|(-?\d+)|([(),.]))/y;
  let at = 0;
  while (at < expression.length) {
    pattern.lastIndex = at;
    const match = pattern.exec(expression);
    if (match === null) {
      if (expression.slice(at).trim() === '') break;
      throw new Error(UNREADABLE);
    }
    const [, quoted, name, number, mark] = match;
    if (quoted !== undefined) found.push({ kind: 'string', text: quoted.replaceAll("''", "'") });
    else if (name !== undefined) found.push({ kind: 'name', text: name });
    else if (number !== undefined) found.push({ kind: 'number', text: number });
    else found.push({ kind: 'mark', text: String(mark) });
    at = pattern.lastIndex;
  }
  return found;
}

/**
 * What a property Azure gives at deploy time reads as: `environment()`'s storage
 * suffix, Azure's own; a client ID, a GUID; the apps environment's domain, Azure's
 * under azurecontainerapps.io; a Communication Services host, its own name under
 * communication.azure.com; the e-mail domain's, a GUID under azurecomm.net; a
 * vault's address, its own name under vault.azure.net. Any other is refused, never
 * guessed. `resource` is the last part of the resource's ID, as Bicep wrote it.
 */
function deployTime(name: string, resource: string | undefined, properties: readonly string[]): Part {
  const property = properties.join('.');
  if (name === 'environment') {
    if (property !== 'suffixes.storage') throw new Error(`environment().${property} is not one this tool reads`);
    return { text: 'core.windows.net' };
  }
  const own = escaped(resource ?? '');
  const known: Readonly<Record<string, string>> = {
    clientId: GUID_PATTERN,
    defaultDomain: `${HOST}\\.azurecontainerapps\\.io`,
    hostName: `${own}\\.[a-z0-9-]+\\.communication\\.azure\\.com`,
    mailFromSenderDomain: `${GUID_PATTERN}\\.azurecomm\\.net`,
    vaultUri: `https://${own}\\.vault\\.azure\\.net/`,
  };
  const pattern = known[property];
  if (pattern === undefined || resource === undefined) {
    throw new Error(`reference(...).${property} is not one this tool reads`);
  }
  return { key: `${resource}.${property}`, pattern };
}

/** `uri(base, relative)`: a vault's address and a path under it, joined as Azure joins them (the base ends in `/`). */
function joinedUri(args: readonly Part[][]): Part[] {
  const [base, relative] = args;
  const last = base?.at(-1);
  const tail = relative?.length === 1 ? relative[0] : undefined;
  if (args.length !== 2 || last === undefined || !('key' in last) || !last.key.endsWith('.vaultUri')) {
    throw new Error("uri()'s base is not a vault's address");
  }
  if (tail === undefined || !('text' in tail) || tail.text.startsWith('/'))
    throw new Error("uri()'s path is not plain");
  return [...(base ?? []), tail];
}

/** The parts an ARM expression Bicep leaves in a snapshot reads as: format, concat, string, and holes; an error for any other. */
function expressionParts(expression: string): Part[] {
  const list = tokens(expression);
  let at = 0;
  const next = (): Token => {
    const token = list[at];
    if (token === undefined) throw new Error(UNREADABLE);
    at += 1;
    return token;
  };
  const isMark = (mark: string): boolean => list[at]?.kind === 'mark' && list[at]?.text === mark;
  const take = (mark: string): void => {
    if (!isMark(mark)) throw new Error(UNREADABLE);
    at += 1;
  };
  const value = (): Part[] => {
    const token = next();
    if (token.kind === 'string' || token.kind === 'number') return [{ text: token.text }];
    if (token.kind !== 'name') throw new Error(UNREADABLE);
    take('(');
    const args: Part[][] = [];
    while (!isMark(')')) {
      if (args.length > 0) take(',');
      args.push(value());
    }
    take(')');
    const properties = propertyChain();
    if (properties.length === 0) return applied(token.text, args);
    if (token.text !== 'reference' && token.text !== 'environment') {
      throw new Error(`${token.text}(...).${properties.join('.')} is not one this tool reads`);
    }
    // Keyed by the resource and property, so one resource's property reads the same in every setting.
    const first = args[0]?.length === 1 ? args[0][0] : undefined;
    const resource = first !== undefined && 'text' in first ? first.text.split('/').at(-1) : undefined;
    return [deployTime(token.text, resource, properties)];
  };
  /** The `.a.b` after a call, if any. */
  const propertyChain = (): string[] => {
    const properties: string[] = [];
    while (isMark('.')) {
      take('.');
      const property = next();
      if (property.kind !== 'name') throw new Error(UNREADABLE);
      properties.push(property.text);
    }
    return properties;
  };
  const parts = value();
  if (at !== list.length) throw new Error(UNREADABLE);
  return parts;
}

/** A function of strings applied: format's {n} places filled, concat's and string's joined. */
function applied(name: string, args: readonly Part[][]): Part[] {
  if (name === 'concat' || (name === 'string' && args.length === 1)) return args.flat();
  if (name === 'uri') return joinedUri(args);
  if (name !== 'format') throw new Error(`${name}() is not one this tool reads`);
  const [shape, ...fill] = args;
  const only = shape?.length === 1 ? shape[0] : undefined;
  if (only === undefined || !('text' in only)) throw new Error("format()'s shape is not plain text");
  return only.text.split(/(\{\d+\})/).flatMap((piece) => {
    const place = /^\{(\d+)\}$/.exec(piece)?.[1];
    if (place === undefined) return piece === '' ? [] : [{ text: piece }];
    const filled = fill[Number(place)];
    if (filled === undefined) throw new Error('format() names a value it is not given');
    return filled;
  });
}

/** Each shell marker in a text, as its hole. */
function marked(text: string): Part[] {
  const markers = Object.entries(SHELL_MARKERS);
  const split = new RegExp(`(${markers.map(([, { marker }]) => escaped(marker)).join('|')})`);
  return text.split(split).flatMap((piece): Part[] => {
    const found = markers.find(([, { marker }]) => marker === piece);
    if (found !== undefined) return [{ key: `shell ${found[0]}`, pattern: found[1].pattern }];
    return piece === '' ? [] : [{ text: piece }];
  });
}

/** What a resolved snapshot value must read as: plain text, or an ARM expression (`[...]`; `[[` is a plain `[`). */
export function partsOf(value: string): Part[] {
  const expression = value.startsWith('[') && !value.startsWith('[[') && value.endsWith(']');
  const parts = expression
    ? expressionParts(value.slice(1, -1))
    : [{ text: value.startsWith('[[') ? value.slice(1) : value }];
  return parts.flatMap((part) => ('text' in part ? marked(part.text) : [part]));
}

/** What a value read on Azure is bound to, by each hole's key: one value per key across everything compared. */
export type Bound = Map<string, string>;

/** Whether a live value reads as the parts do, its holes agreeing with (and then added to) what is bound. */
export function matches(parts: readonly Part[], live: string, bound: Bound): boolean {
  const holes = parts.filter((part): part is Extract<Part, { key: string }> => 'key' in part);
  const pattern = parts.map((part) => ('text' in part ? escaped(part.text) : `(${part.pattern})`)).join('');
  const found = new RegExp(`^${pattern}$`).exec(live);
  if (found === null) return false;
  const read = holes.map((hole, index) => [hole.key, String(found[index + 1])] as const);
  // The same hole twice in one value, or a hole already bound, must read the same.
  const seen = new Map(bound);
  for (const [key, value] of read) {
    if (seen.has(key) && seen.get(key) !== value) return false;
    seen.set(key, value);
  }
  for (const [key, value] of read) bound.set(key, value);
  return true;
}

/** One expected setting: a value's parts, or the secret it refers to. */
type ExpectedSetting = { readonly parts: readonly Part[] } | { readonly secretRef: string };

/** A workload's one container as this commit's templates give it. */
interface Expected {
  readonly command: readonly (readonly Part[])[];
  readonly args: readonly (readonly Part[])[];
  readonly env: ReadonlyMap<string, ExpectedSetting>;
  readonly resources: { readonly cpu: number; readonly memory: string };
  readonly volumeMounts: readonly { readonly volumeName: string; readonly mountPath: string }[];
}

const isRecord = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const wordsOf = (value: unknown, what: string): Part[][] => {
  if (value === undefined) return [];
  if (!Array.isArray(value) || !value.every((word) => typeof word === 'string'))
    throw new Error(`its ${what} is not a list of words`);
  return value.map(partsOf);
};

/**
 * The one container of a snapshotted workload's template (`containers`), as
 * expected, or an error saying why it can't be read: Bicep gave another shape.
 */
export function expectedOf(containers: unknown): Expected {
  if (!Array.isArray(containers) || containers.length !== 1 || !isRecord(containers[0])) {
    throw new Error('the template must give exactly one container');
  }
  const { command, args, env, resources, volumeMounts } = containers[0];
  const settings = new Map<string, ExpectedSetting>();
  for (const entry of Array.isArray(env) ? (env as unknown[]) : []) {
    const { name, value, secretRef } = isRecord(entry) ? entry : {};
    if (typeof name !== 'string' || settings.has(name))
      throw new Error('a setting has no name, or the same name twice');
    if (typeof secretRef === 'string') settings.set(name, { secretRef });
    else if (typeof value === 'string') settings.set(name, { parts: partsOf(value) });
    else throw new Error(`the setting ${name} has neither a value nor a secret reference`);
  }
  const size = isRecord(resources) ? resources : {};
  if (typeof size.cpu !== 'number' || typeof size.memory !== 'string') throw new Error('its size is not given');
  const mounts = (Array.isArray(volumeMounts) ? (volumeMounts as unknown[]) : []).map((mount) => {
    const { volumeName, mountPath } = isRecord(mount) ? mount : {};
    if (typeof volumeName !== 'string' || typeof mountPath !== 'string')
      throw new Error('a mount is not a volume and a path');
    return { volumeName, mountPath };
  });
  return {
    command: wordsOf(command, 'command'),
    args: wordsOf(args, 'arguments'),
    env: settings,
    resources: { cpu: size.cpu, memory: size.memory },
    volumeMounts: mounts,
  };
}

const wordsMatch = (expected: readonly (readonly Part[])[], live: readonly string[], bound: Bound): boolean =>
  expected.length === live.length && expected.every((parts, index) => matches(parts, String(live[index]), bound));

const mountKey = (mount: { readonly volumeName: string; readonly mountPath: string }): string =>
  JSON.stringify([mount.volumeName, mount.mountPath]);

/** How a live container's settings differ from the expected, by name alone. */
function settingDifferences(expected: Expected, live: LiveContainer, bound: Bound): string[] {
  const said: string[] = [];
  const names = live.env.map((setting) => setting.name);
  if (new Set(names).size !== names.length) said.push('it names a setting twice');
  for (const setting of live.env) {
    const want = expected.env.get(setting.name);
    if (want === undefined) said.push(`it has a setting the template doesn't: ${shown(setting.name)}`);
    else if ('secretRef' in want) {
      if (!('secretRef' in setting) || setting.secretRef !== want.secretRef) {
        said.push(`its setting ${shown(setting.name)} doesn't read the secret the template names`);
      }
    } else if (!('value' in setting))
      said.push(`its setting ${shown(setting.name)} reads a secret where the template gives a value`);
    else if (setting.name !== RELEASE_SETTING && !matches(want.parts, setting.value, bound)) {
      said.push(`its setting ${shown(setting.name)} holds another value than the template gives`);
    }
  }
  for (const name of expected.env.keys()) {
    if (!names.includes(name)) said.push(`it lacks the template's setting ${shown(name)}`);
  }
  return said;
}

/**
 * Every way a live container differs from what the template expects, beyond its
 * image and AGENTX_RELEASE's value, in words with no value; none when it is as
 * deployed. `bound` holds what each hole read, across both workloads.
 */
export function differences(expected: Expected, live: LiveContainer, bound: Bound): string[] {
  const said: string[] = [];
  if (!wordsMatch(expected.command, live.command, bound)) said.push('its command is not the template’s');
  if (!wordsMatch(expected.args, live.args, bound)) said.push('its arguments are not the template’s');
  said.push(...settingDifferences(expected, live, bound));
  if (live.resources.cpu !== expected.resources.cpu || live.resources.memory !== expected.resources.memory) {
    said.push('its size is not the template’s');
  }
  const mounts = (list: LiveContainer['volumeMounts']): string => list.map(mountKey).sort().join(' ');
  if (mounts(live.volumeMounts) !== mounts(expected.volumeMounts)) said.push('its mounts are not the template’s');
  return said;
}

/** A value with no hole, as plain text, or an error: one only Azure or the shell gives can't be sent from here. */
function plain(parts: readonly Part[], what: string): string {
  return parts
    .map((part) => {
      if ('text' in part) return part.text;
      throw new Error(`${what} is given only at deploy time, so it can't be sent from the template alone`);
    })
    .join('');
}

/**
 * The container a deployment of this template sends, with the image and build
 * given, in the shape a release reads (release.ts `runningAs`, field for field),
 * or an error when any value is Azure's to give at deploy time or the shell's.
 */
export function deployable(
  name: string,
  containers: unknown,
  image: string,
  release: string,
): LiveContainer & { readonly name: string; readonly image: string } {
  const expected = expectedOf(containers);
  const words = (list: Expected['command'], what: string): string[] => list.map((parts) => plain(parts, what));
  return {
    name,
    image,
    command: words(expected.command, 'a word of its command'),
    args: words(expected.args, 'an argument'),
    env: [...expected.env].map(([setting, want]) => {
      if ('secretRef' in want) return { name: setting, secretRef: want.secretRef };
      return {
        name: setting,
        value: setting === RELEASE_SETTING ? release : plain(want.parts, `the setting ${setting}`),
      };
    }),
    resources: expected.resources,
    volumeMounts: expected.volumeMounts,
  };
}

/** A workload as Azure gives it, or a snapshot predicts it: what runs it, and its properties. */
export interface Workload {
  readonly identity: unknown;
  readonly properties: unknown;
}

const recordIn = (value: unknown, ...path: readonly string[]): Readonly<Record<string, unknown>> => {
  let found: unknown = value;
  for (const key of path) found = isRecord(found) ? found[key] : undefined;
  return isRecord(found) ? found : {};
};

/** A workload's template's containers. */
export const containersOf = (workload: unknown): unknown => recordIn(workload, 'properties', 'template').containers;

/** Absent, as Azure writes it: null, an empty list or an empty object. */
const absent = (value: unknown): boolean =>
  value === undefined ||
  value === null ||
  (Array.isArray(value) && value.length === 0) ||
  (isRecord(value) && Object.keys(value).length === 0);

/** A value with every absent field left out and objects' keys in order, so Azure's nulls read as the snapshot's nothing. */
function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (!isRecord(value)) return value;
  return Object.fromEntries(
    Object.keys(value)
      .filter((key) => !absent(value[key]))
      .sort()
      .map((key) => [key, canonical(value[key])]),
  );
}

const same = (one: unknown, other: unknown): boolean =>
  JSON.stringify(canonical(absent(one) ? undefined : one)) ===
  JSON.stringify(canonical(absent(other) ? undefined : other));

/** The fields compared as they are, absent being absent, by where they sit. */
const AS_THEY_ARE: Readonly<Record<'jobs' | 'containerApps', readonly (readonly string[])[]>> = {
  jobs: [
    ['configuration', 'triggerType'],
    ['configuration', 'replicaTimeout'],
    ['configuration', 'replicaRetryLimit'],
    ['configuration', 'manualTriggerConfig'],
    ['configuration', 'scheduleTriggerConfig'],
    ['configuration', 'eventTriggerConfig'],
  ],
  containerApps: [
    ['configuration', 'ingress', 'external'],
    ['configuration', 'ingress', 'allowInsecure'],
    ['configuration', 'ingress', 'targetPort'],
    ['configuration', 'ingress', 'traffic'],
    ['configuration', 'ingress', 'ipSecurityRestrictions'],
    ['configuration', 'ingress', 'customDomains'],
    ['configuration', 'ingress', 'additionalPortMappings'],
    ['configuration', 'ingress', 'clientCertificateMode'],
    ['configuration', 'ingress', 'corsPolicy'],
    ['configuration', 'ingress', 'stickySessions'],
    ['configuration', 'service'],
    ['configuration', 'runtime'],
    ['template', 'scale', 'maxReplicas'],
    ['template', 'scale', 'rules'],
    ['template', 'terminationGracePeriodSeconds'],
    ['template', 'serviceBinds'],
  ],
};

/** The fields both kinds compare as they are. */
const BOTH: readonly (readonly string[])[] = [
  ['configuration', 'registries'],
  ['configuration', 'dapr'],
  ['configuration', 'identitySettings'],
  ['template', 'initContainers'],
];

const at = (value: unknown, path: readonly string[]): unknown =>
  recordIn(value, ...path.slice(0, -1))[String(path.at(-1))];

/** Lower case, for what Azure writes in either case (resource IDs, `Auto`). */
const lower = (value: unknown): string => (typeof value === 'string' ? value.toLowerCase() : JSON.stringify(value));

/** How the workload's secrets differ: each from the vault, by its identity, with no value in hand; by name alone. */
function secretDifferences(expected: unknown, live: unknown, bound: Bound): string[] {
  const listOf = (workload: unknown): readonly Readonly<Record<string, unknown>>[] => {
    const secrets = recordIn(workload, 'properties', 'configuration').secrets;
    return Array.isArray(secrets) ? secrets.map((secret) => recordIn(secret)) : [];
  };
  const want = new Map(listOf(expected).map((secret) => [String(secret.name), secret]));
  const said: string[] = [];
  const names = new Set<string>();
  for (const secret of listOf(live)) {
    const name = String(secret.name);
    names.add(name);
    const wanted = want.get(name);
    const extra = Object.keys(secret).filter(
      (key) => !['name', 'keyVaultUrl', 'identity'].includes(key) && !absent(secret[key]),
    );
    if (wanted === undefined) said.push(`it has a secret the template doesn't: ${shown(name)}`);
    else if (extra.length > 0)
      said.push(`its secret ${shown(name)} holds ${extra.map(shown).join(', ')}, not only a vault reference`);
    else if (
      typeof secret.keyVaultUrl !== 'string' ||
      !matches(partsOf(String(wanted.keyVaultUrl)), secret.keyVaultUrl, bound)
    ) {
      said.push(`its secret ${shown(name)} is read from another vault entry than the template’s`);
    } else if (lower(secret.identity) !== lower(wanted.identity)) {
      said.push(`its secret ${shown(name)} is read as another identity than the template’s`);
    }
  }
  for (const name of want.keys()) if (!names.has(name)) said.push(`it lacks the template's secret ${shown(name)}`);
  return said;
}

/** A workload's volumes, each with its secrets in path order, so only what they hold counts. */
function volumesOf(workload: unknown): unknown {
  const volumes = recordIn(workload, 'properties', 'template').volumes;
  if (!Array.isArray(volumes)) return volumes;
  return (volumes as unknown[]).map((volume) => {
    const { secrets, ...rest } = recordIn(volume);
    const sorted = Array.isArray(secrets)
      ? (secrets as unknown[]).map((secret) => JSON.stringify(canonical(secret))).toSorted()
      : secrets;
    return { ...rest, secrets: sorted };
  });
}

/** The identities a workload runs as, by their resource IDs in lower case (Azure lowers `resourceGroups`). */
const identitiesOf = (workload: unknown): string =>
  JSON.stringify([
    lower(recordIn(workload, 'identity').type),
    ...Object.keys(recordIn(workload, 'identity', 'userAssignedIdentities'))
      .map(lower)
      .sort(),
  ]);

/**
 * How many inactive revisions Azure keeps when an app sets none: "By default, you have access to 100 inactive
 * revisions" (learn.microsoft.com/azure/container-apps/revisions). apps.bicep sets none. Staging in fact lists more
 * (201 on 13 Nov 2026: Azure purges late), so the release's test of a list at that cap (release.ts recordedBuilds) is
 * in practice its test of a flood; GitHub's record of the last release (anchor.ts) is what a purge can't reach.
 */
const DEFAULT_INACTIVE_REVISIONS = 100;

/**
 * An app's own checks: its least replicas 0 or 1 (`apps --keep-running` sets 1), and the inactive revisions it keeps
 * as its template does, absent read as Azure's default: the release reads them as the record of what ran
 * (release.ts recordedBuilds), and a 0 would purge that record.
 */
function appDifferences(expected: unknown, live: unknown): string[] {
  const said: string[] = [];
  if (![0, 1].includes(Number(at(live, ['properties', 'template', 'scale', 'minReplicas'])))) {
    said.push('its template.scale.minReplicas is neither 0 nor 1');
  }
  const kept = (workload: unknown): unknown =>
    at(workload, ['properties', 'configuration', 'maxInactiveRevisions']) ?? DEFAULT_INACTIVE_REVISIONS;
  if (kept(expected) !== kept(live)) said.push('its configuration.maxInactiveRevisions is not the template’s');
  return said;
}

/**
 * Every way a workload differs from its template beyond its containers (AZ2c):
 * no init container; the same volumes, secrets (each a vault reference as its
 * identity, never a value), identities, registries, environment and plan; a
 * job's trigger, time limit and runs; an app's door, scale, grace and kept
 * revisions. In words with no value.
 */
export function workloadDifferences(
  kind: 'jobs' | 'containerApps',
  expected: unknown,
  live: unknown,
  bound: Bound,
): string[] {
  const said: string[] = [];
  for (const path of [...BOTH, ...AS_THEY_ARE[kind]]) {
    if (!same(at(expected, ['properties', ...path]), at(live, ['properties', ...path]))) {
      said.push(`its ${path.join('.')} is not the template’s`);
    }
  }
  for (const path of [
    ['environmentId'],
    ['workloadProfileName'],
    ['configuration', 'ingress', 'transport'],
    ['configuration', 'activeRevisionsMode'],
  ]) {
    const want = at(expected, ['properties', ...path]);
    const found = at(live, ['properties', ...path]);
    // An app's revisions mode Azure gives as Single when the template sends none.
    const wanted = want ?? (path.at(-1) === 'activeRevisionsMode' && kind === 'containerApps' ? 'Single' : undefined);
    if (lower(wanted ?? null) !== lower(found ?? null)) said.push(`its ${path.join('.')} is not the template’s`);
  }
  if (kind === 'containerApps') said.push(...appDifferences(expected, live));
  if (identitiesOf(expected) !== identitiesOf(live)) said.push('it runs as other identities than the template’s');
  if (!same(volumesOf(expected), volumesOf(live))) said.push('its volumes are not the template’s');
  return [...said, ...secretDifferences(expected, live, bound)];
}

/** A resource the apps deployment makes, by its type and name. */
interface Named {
  readonly type: string;
  readonly name: string;
}

/**
 * What a deploy/azure folder's apps.bicep gives each named workload (its
 * identity and properties), from the pinned Bicep's snapshot of the apps
 * deployment in the subscription, as a plain `apps` (no load run) sends it, the
 * shell's values as their markers. An error when Bicep can't, or a resource
 * isn't made exactly once. `source` is this checkout's folder unless given.
 */
export function templatesIn(subscription: string, wanted: readonly Named[], source?: string): Workload[] {
  const values = Object.fromEntries(Object.entries(SHELL_MARKERS).map(([variable, { marker }]) => [variable, marker]));
  const made = inCopy(
    (dir) =>
      deploymentSnapshot(
        dir,
        DEPLOYMENTS.apps,
        RESOURCE_GROUP,
        { ...values, AGENTX_AZURE_LOAD_RUN: 'false' },
        subscription,
      ),
    source,
  ).predictedResources;
  return wanted.map(({ type, name }) => {
    const found = made.filter((resource) => resource.type === type && resource.name === name);
    const [one] = found;
    if (one === undefined || found.length > 1)
      throw new Error(`apps.bicep makes ${String(found.length)} of ${name}, not one`);
    return { identity: one.identity, properties: one.properties };
  });
}
