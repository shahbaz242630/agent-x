// Vitest global setup for the end-to-end suite (vitest.e2e.config.ts): FX-IDP.
// With the compose stack up, it takes Zitadel's automation token out of the
// stack and provisions what the login tests need, named by this run: an OIDC
// client, a user with a password and no second factor, and a user with an
// authenticator app, then waits until the login can see both. It reads the
// policies the tests assert on. Teardown removes what it created. It also
// registers the API as the login service's client and starts it with sign-in
// on (api-sign-in.ts), with a user of its own for the sign-in tests; that
// registration is the stack's, and stays.
import { randomBytes } from 'node:crypto';

import type { TestProject } from 'vitest/node';

import { type ApiSignIn, apiSignIn } from './api-sign-in.ts';
import { LOGIN_ORIGIN, readAutomationToken } from './compose.ts';
import { totp } from './totp.ts';
import {
  addOtpEmail,
  createHumanUser,
  createOidcApp,
  deleteProject,
  deleteUser,
  impersonationEnabled,
  type LoginPolicy,
  loginPolicy,
  loginSees,
  registerTotp,
  verifyTotp,
  zitadelClient,
} from './zitadel.ts';

/** Where the OIDC callback listens; the redirect URI is registered with the client. */
export const CALLBACK_PORT = 4319;
export const REDIRECT_URI = `http://127.0.0.1:${String(CALLBACK_PORT)}/callback`;

export interface TestUser {
  readonly userId: string;
  readonly loginName: string;
}

export interface E2eFixtures {
  readonly issuer: string;
  readonly clientId: string;
  readonly redirectUri: string;
  /** The same password for both test users; random for this run, never written down. */
  readonly password: string;
  readonly users: {
    /** A password and nothing else: the login must not complete without a second factor. */
    readonly noFactor: TestUser;
    /** A password and an authenticator app whose secret the test holds. */
    readonly totp: TestUser & { readonly totpSecret: string };
    /** As `totp`, for the sign-in through the API alone, so no code is ever used twice across the two files. */
    readonly signIn: TestUser & { readonly totpSecret: string };
    /** As `totp`, for the step-up through the API (B3-3b). */
    readonly stepUpApp: TestUser & { readonly totpSecret: string };
    /** A password and no second factor yet: the step-up tests register a (virtual) security key at its first sign-in. */
    readonly stepUpKey: TestUser;
    /**
     * As `stepUpKey`, invited by the operator as a new organisation's first admin (B4-6d); registers a
     * (virtual) security key at its first sign-in, as an admin needs a passkey (B3+-1, SEC-HA-12). The
     * address is Zitadel's verified `<username>@agentx.localhost`.
     */
    readonly firstAdmin: TestUser;
    /** As `totp`, invited by the first admin, then made an admin, which their app code can't use, and deactivated (B4-6d-2). */
    readonly member: TestUser & { readonly totpSecret: string };
    /** A password, an authenticator app and codes by email: every second factor removed by a reset (B6-3c). */
    readonly resetTarget: TestUser;
  };
  /** The API as the login service's client. */
  readonly api: ApiSignIn;
  readonly policy: LoginPolicy;
  readonly impersonation: boolean;
}

declare module 'vitest' {
  export interface ProvidedContext {
    e2e: E2eFixtures;
  }
}

export default async function setup(project: TestProject): Promise<() => Promise<void>> {
  const client = zitadelClient(LOGIN_ORIGIN, await readAutomationToken());
  const run = `e2e-${randomBytes(4).toString('hex')}`;
  const password = `${randomBytes(12).toString('hex')}aZ9!`;

  // The project is created first and named up front, so a failure at any later
  // step (the app included) can remove it.
  const { id: projectId } = await client.post<{ id: string }>('/management/v1/projects', { name: run });
  const app = { projectId, clientId: '' };
  const created: TestUser[] = [];
  /** A user named for this run, recorded for removal before anything else is done to it. */
  const newUser = async (name: string): Promise<TestUser> => {
    const user = await createHumanUser(client, `${run}-${name}`, password);
    created.push(user);
    return user;
  };
  /** As newUser, with an authenticator app registered and verified: the user and the app's secret. */
  const newUserWithApp = async (name: string): Promise<readonly [TestUser, string]> => {
    const user = await newUser(name);
    const secret = await registerTotp(client, user.userId);
    await verifyTotp(client, user.userId, totp(secret, Date.now()));
    return [user, secret];
  };
  const removeAll = () =>
    Promise.allSettled([
      ...created.map((user) => deleteUser(client, user.userId)),
      deleteProject(client, app.projectId),
    ]);
  try {
    app.clientId = (await createOidcApp(client, projectId, run, REDIRECT_URI)).clientId;
    const noFactor = await newUser('nofactor');
    const [withTotp, totpSecret] = await newUserWithApp('totp');
    const [signIn, signInSecret] = await newUserWithApp('signin');
    const [stepUpApp, stepUpSecret] = await newUserWithApp('stepup-app');
    const stepUpKey = await newUser('stepup-key');
    const firstAdmin = await newUser('first-admin');
    const [member, memberSecret] = await newUserWithApp('member');
    const [resetTarget] = await newUserWithApp('reset-target');
    await addOtpEmail(client, resetTarget.userId);
    await loginSees(client, noFactor, ['AUTHENTICATION_METHOD_TYPE_PASSWORD']);
    await loginSees(client, stepUpKey, ['AUTHENTICATION_METHOD_TYPE_PASSWORD']);
    await loginSees(client, stepUpApp, ['AUTHENTICATION_METHOD_TYPE_PASSWORD', 'AUTHENTICATION_METHOD_TYPE_TOTP']);
    await loginSees(client, withTotp, ['AUTHENTICATION_METHOD_TYPE_PASSWORD', 'AUTHENTICATION_METHOD_TYPE_TOTP']);
    await loginSees(client, signIn, ['AUTHENTICATION_METHOD_TYPE_PASSWORD', 'AUTHENTICATION_METHOD_TYPE_TOTP']);
    await loginSees(client, firstAdmin, ['AUTHENTICATION_METHOD_TYPE_PASSWORD']);
    await loginSees(client, member, ['AUTHENTICATION_METHOD_TYPE_PASSWORD', 'AUTHENTICATION_METHOD_TYPE_TOTP']);
    await loginSees(client, resetTarget, [
      'AUTHENTICATION_METHOD_TYPE_PASSWORD',
      'AUTHENTICATION_METHOD_TYPE_TOTP',
      'AUTHENTICATION_METHOD_TYPE_OTP_EMAIL',
    ]);
    const api = await apiSignIn(client);

    project.provide('e2e', {
      issuer: LOGIN_ORIGIN,
      clientId: app.clientId,
      redirectUri: REDIRECT_URI,
      password,
      users: {
        noFactor,
        totp: { ...withTotp, totpSecret },
        signIn: { ...signIn, totpSecret: signInSecret },
        stepUpApp: { ...stepUpApp, totpSecret: stepUpSecret },
        stepUpKey,
        firstAdmin,
        member: { ...member, totpSecret: memberSecret },
        resetTarget,
      },
      api,
      policy: await loginPolicy(client),
      impersonation: await impersonationEnabled(client),
    });
  } catch (error) {
    await removeAll();
    throw error;
  }

  return async () => {
    await removeAll();
  };
}
