// A client registering itself (RFC 7591; SEC-OAUTH-13): what it says of
// itself, checked, before anything is kept. Public clients alone (decision 3:
// `none`, no secret), the code flow or the device flow (6E3c), refresh
// tokens always. Its name is
// what it says it is, never proof of anything: the consent page shows it as
// such, with the redirect address's host in bold. Its logo and its pages are
// never fetched.
import { visibleName } from '../../../shared-kernel/index.ts';
import { isLoopback, redirectProblems } from '../domain/redirects.ts';
import { scopesAsked } from './scopes.ts';

/** The most redirect addresses one client registers. */
export const MOST_REDIRECTS = 5;

/** The most characters a client's name keeps, as an agent's. */
const MOST_NAME = 100;

/** The most characters of a software ID or version. */
const MOST_SOFTWARE = 255;

/** The device flow's grant type (RFC 8628 §3.4). */
export const DEVICE_CODE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';

/** The grant types a client may register: the code flow, its refresh tokens, and the device flow (6E3c). */
export const GRANT_TYPES = ['authorization_code', 'refresh_token', DEVICE_CODE_GRANT] as const;
export type GrantType = (typeof GRANT_TYPES)[number];

/** A client's registration, checked: what is kept. */
export interface ClientRegistration {
  readonly name: string;
  readonly redirectUris: readonly string[];
  /** `native` when every address is the machine's own loopback (a CLI, a desktop app), else `web`. */
  readonly applicationType: 'web' | 'native';
  readonly grantTypes: readonly GrantType[];
  readonly softwareId: string | null;
  readonly softwareVersion: string | null;
}

/** RFC 7591 §3.2.2's two errors. */
type RegistrationError = 'invalid_redirect_uri' | 'invalid_client_metadata';

export type RegistrationChecked =
  | { readonly outcome: 'valid'; readonly client: ClientRegistration }
  | { readonly outcome: 'invalid'; readonly error: RegistrationError; readonly description: string };

/** What a client may send: everything optional here, each checked below, so a refusal is RFC 7591's own. */
export interface RegistrationAsked {
  readonly redirect_uris?: readonly string[] | undefined;
  readonly client_name?: string | undefined;
  readonly grant_types?: readonly string[] | undefined;
  readonly response_types?: readonly string[] | undefined;
  readonly token_endpoint_auth_method?: string | undefined;
  readonly scope?: string | undefined;
  readonly software_id?: string | undefined;
  readonly software_version?: string | undefined;
}

const invalid = (error: RegistrationError, description: string): RegistrationChecked => ({
  outcome: 'invalid',
  error,
  description,
});

export const isGrantType = (value: string): value is GrantType => GRANT_TYPES.some((grant) => grant === value);

/** A short text the client may send, or null for none; undefined for one past its length. */
const shortText = (value: string | undefined): string | null | undefined => {
  if (value === undefined || value === '') return null;
  return value.length <= MOST_SOFTWARE ? value : undefined;
};

/** The name the client gave, if it is a visible one, or the first redirect address's host. */
function nameOf(asked: string | undefined, firstRedirect: string): string {
  const given = asked === undefined ? undefined : visibleName(asked, MOST_NAME);
  if (given?.problems.length === 0) return given.name;
  return new URL(firstRedirect).host.slice(0, MOST_NAME);
}

/** The registration as checked: valid, with what is kept; or RFC 7591's error, with why. */
export function checkRegistration(asked: RegistrationAsked): RegistrationChecked {
  const redirects = asked.redirect_uris ?? [];
  if (redirects.length === 0 || redirects.length > MOST_REDIRECTS) {
    return invalid('invalid_redirect_uri', `register 1 to ${String(MOST_REDIRECTS)} redirect addresses`);
  }
  if (new Set(redirects).size !== redirects.length) return invalid('invalid_redirect_uri', 'an address is given twice');
  const problems = redirects.flatMap(redirectProblems);
  if (problems.length > 0) return invalid('invalid_redirect_uri', problems.join('; '));
  const method = asked.token_endpoint_auth_method ?? 'none';
  if (method !== 'none') return invalid('invalid_client_metadata', 'only public clients register: none');
  const responses = asked.response_types ?? ['code'];
  if (responses.length !== 1 || responses[0] !== 'code') {
    return invalid('invalid_client_metadata', 'the only response type is code');
  }
  const grants = asked.grant_types ?? ['authorization_code', 'refresh_token'];
  if (grants.length === 0 || !grants.every(isGrantType) || !grants.some((grant) => grant !== 'refresh_token')) {
    return invalid(
      'invalid_client_metadata',
      'grant types are authorization_code or the device code, with refresh_token',
    );
  }
  if (scopesAsked(asked.scope) === undefined) return invalid('invalid_client_metadata', 'a scope is not one there is');
  const [softwareId, softwareVersion] = [shortText(asked.software_id), shortText(asked.software_version)];
  if (softwareId === undefined || softwareVersion === undefined) {
    return invalid(
      'invalid_client_metadata',
      `a software ID or version is at most ${String(MOST_SOFTWARE)} characters`,
    );
  }
  const [first = ''] = redirects;
  return {
    outcome: 'valid',
    client: {
      name: nameOf(asked.client_name, first),
      redirectUris: [...redirects],
      applicationType: redirects.every(isLoopback) ? 'native' : 'web',
      // Refresh tokens always (decision 5), whatever was asked: a client without one would be cut off within the hour.
      grantTypes: [...new Set<GrantType>([...grants.filter(isGrantType), 'refresh_token'])],
      softwareId,
      softwareVersion,
    },
  };
}
