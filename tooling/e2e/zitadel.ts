// The parts of Zitadel's API the end-to-end suite uses, through the stack's
// edge, as the automation machine user: reading the login and security
// policies, and creating the test users and the OIDC client the login tests
// need (FX-IDP). Everything created here is named by the run and removed by
// the suite's teardown.
export interface ZitadelClient {
  get<T>(path: string): Promise<T>;
  post<T>(path: string, body?: unknown): Promise<T>;
  delete(path: string): Promise<void>;
}

export function zitadelClient(origin: string, token: string): ZitadelClient {
  const call = async <T>(method: string, path: string, body?: unknown): Promise<T> => {
    const response = await fetch(`${origin}${path}`, {
      method,
      headers: {
        authorization: `Bearer ${token}`,
        accept: 'application/json',
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const text = await response.text();
    if (!response.ok) throw new Error(`Zitadel ${method} ${path} failed: ${String(response.status)} ${text}`);
    return (text === '' ? {} : JSON.parse(text)) as T;
  };
  return {
    get: (path) => call('GET', path),
    post: (path, body) => call('POST', path, body ?? {}),
    delete: async (path) => {
      await call('DELETE', path);
    },
  };
}

export interface LoginPolicy {
  readonly forceMfa: boolean;
  readonly allowRegister: boolean;
  readonly allowExternalIdp: boolean;
  readonly passwordlessType: string;
  readonly secondFactors: readonly string[];
  readonly multiFactors: readonly string[];
  readonly mfaInitSkipLifetime: string;
  readonly secondFactorCheckLifetime: string;
  readonly multiFactorCheckLifetime: string;
}

/** The instance's login policy (ADR-003 §2), with the absent booleans read as false, as Zitadel means them. */
export async function loginPolicy(client: ZitadelClient): Promise<LoginPolicy> {
  const { policy } = await client.get<{ policy: Partial<LoginPolicy> }>('/admin/v1/policies/login');
  return {
    forceMfa: policy.forceMfa ?? false,
    allowRegister: policy.allowRegister ?? false,
    allowExternalIdp: policy.allowExternalIdp ?? false,
    passwordlessType: policy.passwordlessType ?? 'PASSWORDLESS_TYPE_NOT_ALLOWED',
    secondFactors: policy.secondFactors ?? [],
    multiFactors: policy.multiFactors ?? [],
    mfaInitSkipLifetime: policy.mfaInitSkipLifetime ?? '',
    secondFactorCheckLifetime: policy.secondFactorCheckLifetime ?? '',
    multiFactorCheckLifetime: policy.multiFactorCheckLifetime ?? '',
  };
}

/** Whether an admin may impersonate users (ADR-003 §4: never). */
export async function impersonationEnabled(client: ZitadelClient): Promise<boolean> {
  const { policy } = await client.get<{ policy: { enableImpersonation?: boolean } }>('/admin/v1/policies/security');
  return policy.enableImpersonation ?? false;
}

/**
 * A public web client (authorization code with PKCE, no secret) in an
 * existing project, in development mode so its redirect may be plain http on
 * the loopback address.
 */
export async function createOidcApp(
  client: ZitadelClient,
  projectId: string,
  name: string,
  redirectUri: string,
): Promise<{ clientId: string }> {
  const { clientId } = await client.post<{ clientId: string }>(`/management/v1/projects/${projectId}/apps/oidc`, {
    name,
    redirectUris: [redirectUri],
    responseTypes: ['OIDC_RESPONSE_TYPE_CODE'],
    grantTypes: ['OIDC_GRANT_TYPE_AUTHORIZATION_CODE'],
    appType: 'OIDC_APP_TYPE_WEB',
    authMethodType: 'OIDC_AUTH_METHOD_TYPE_NONE',
    accessTokenType: 'OIDC_TOKEN_TYPE_BEARER',
    devMode: true,
  });
  return { clientId };
}

export const deleteProject = (client: ZitadelClient, projectId: string): Promise<void> =>
  client.delete(`/management/v1/projects/${projectId}`);

export interface HumanUser {
  readonly userId: string;
  /** What the user types on the login page. */
  readonly loginName: string;
}

/** A user with a verified email and a password that needs no change, so the login goes straight to the factors. */
export async function createHumanUser(client: ZitadelClient, username: string, password: string): Promise<HumanUser> {
  const { userId } = await client.post<{ userId: string }>('/v2/users/human', {
    username,
    profile: { givenName: 'End-to-end', familyName: username },
    email: { email: `${username}@agentx.localhost`, isVerified: true },
    password: { password, changeRequired: false },
  });
  const { user } = await client.get<{ user: { preferredLoginName: string } }>(`/v2/users/${userId}`);
  return { userId, loginName: user.preferredLoginName };
}

export const deleteUser = (client: ZitadelClient, userId: string): Promise<void> =>
  client.delete(`/v2/users/${userId}`);

/** Starts an authenticator-app registration for the user and returns its secret, as the app would scan it. */
export async function registerTotp(client: ZitadelClient, userId: string): Promise<string> {
  const { secret } = await client.post<{ secret: string; uri: string }>(`/v2/users/${userId}/totp`);
  return secret;
}

/** Completes the registration with a code from the secret. */
export const verifyTotp = (client: ZitadelClient, userId: string, code: string): Promise<unknown> =>
  client.post(`/v2/users/${userId}/totp/verify`, { code });
