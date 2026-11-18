// The scopes an OAuth client may ask for (RFC 6749 §3.3; SEC-OAUTH-08): the
// agents' own (agents/domain/agent.ts), and `offline_access`, which asks for a
// refresh token (ChatGPT needs it named) and which every connection is given
// anyway (decision 5). What a connection holds is what the person ticked, of
// what the client asked and the agent holds; a refresh may only narrow it.
import { type Scope, SCOPES } from '../../agents/index.ts';

/** Asks for a refresh token: always given, so it changes nothing kept. */
export const OFFLINE_ACCESS = 'offline_access';

/** Every scope the server advertises, in order. */
export const SCOPES_SUPPORTED: readonly string[] = [...SCOPES, OFFLINE_ACCESS];

/** The most characters a scope parameter may have: every scope there is, with room to spare. */
const MOST_CHARACTERS = 256;

const isScope = (word: string): word is Scope => SCOPES.some((scope) => scope === word);

/**
 * The agents' scopes a `scope` parameter asks for, in SCOPES' order, or undefined for one that can't be taken
 * (`invalid_scope`): a word that is no scope, or a word twice. None named but `offline_access`, or no parameter at
 * all, asks for every scope: the person ticks which on the consent page.
 */
export function scopesAsked(parameter: string | undefined): readonly Scope[] | undefined {
  if (parameter === undefined || parameter.trim() === '') return SCOPES;
  if (parameter.length > MOST_CHARACTERS) return undefined;
  const words = parameter.split(' ').filter((word) => word !== '');
  if (new Set(words).size !== words.length) return undefined;
  if (!words.every((word) => word === OFFLINE_ACCESS || isScope(word))) return undefined;
  const asked = words.filter(isScope);
  return asked.length === 0 ? SCOPES : SCOPES.filter((scope) => asked.includes(scope));
}

/**
 * The scopes a refresh asks for, which may only narrow those held: none named keeps them all; one held by no token of
 * the connection is undefined (`invalid_scope`).
 */
export function scopesNarrowed(parameter: string | undefined, held: readonly Scope[]): readonly Scope[] | undefined {
  if (parameter === undefined || parameter.trim() === '') return held;
  const asked = scopesAsked(parameter);
  if (asked === undefined) return undefined;
  const named = parameter.split(' ').some((word) => isScope(word));
  if (!named) return held;
  return asked.every((scope) => held.includes(scope)) ? asked : undefined;
}

/** The scopes as a token answer names them (RFC 6749 §5.1): space-delimited. */
export const scopeParameter = (scopes: readonly Scope[]): string => scopes.join(' ');
