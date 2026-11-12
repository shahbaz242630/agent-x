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
const shown = (name: string): string => name.replace(/[^\w.-]/g, '?');

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
 * communication.azure.com; the e-mail domain's, a GUID under azurecomm.net; any
 * other a host. `resource` is the last part of the resource's ID, as Bicep wrote it.
 */
function deployTime(name: string, resource: string | undefined, properties: readonly string[]): Part {
  const property = properties.join('.');
  if (name === 'environment') {
    if (property !== 'suffixes.storage') throw new Error(`environment().${property} is not one this tool reads`);
    return { text: 'core.windows.net' };
  }
  const known: Readonly<Record<string, string>> = {
    clientId: GUID_PATTERN,
    defaultDomain: `${HOST}\\.azurecontainerapps\\.io`,
    hostName: `${escaped(resource ?? '')}\\.[a-z0-9-]+\\.communication\\.azure\\.com`,
    mailFromSenderDomain: `${GUID_PATTERN}\\.azurecomm\\.net`,
  };
  return { key: `${String(resource)}.${property}`, pattern: known[property] ?? HOST };
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

/** A resource the apps deployment makes, by its type and name. */
interface Named {
  readonly type: string;
  readonly name: string;
}

/**
 * What this folder's apps.bicep gives each named resource's containers (its
 * template's `containers`), from the pinned Bicep's snapshot of the apps
 * deployment in the subscription, as a plain `apps` (no load run) sends it, the
 * shell's values as their markers. An error when Bicep can't, or a resource
 * isn't made exactly once.
 */
export function templatesIn(subscription: string, wanted: readonly Named[]): unknown[] {
  const values = Object.fromEntries(Object.entries(SHELL_MARKERS).map(([variable, { marker }]) => [variable, marker]));
  const made = inCopy((dir) =>
    deploymentSnapshot(
      dir,
      DEPLOYMENTS.apps,
      RESOURCE_GROUP,
      { ...values, AGENTX_AZURE_LOAD_RUN: 'false' },
      subscription,
    ),
  ).predictedResources;
  return wanted.map(({ type, name }) => {
    const found = made.filter((resource) => resource.type === type && resource.name === name);
    const [one] = found;
    if (one === undefined || found.length > 1)
      throw new Error(`apps.bicep makes ${String(found.length)} of ${name}, not one`);
    const properties = isRecord(one.properties) ? one.properties : {};
    return (isRecord(properties.template) ? properties.template : {}).containers;
  });
}
