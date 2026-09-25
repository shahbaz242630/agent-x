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
    /** As `totp`, invited by the operator as a new organisation's first admin (B4-6d); the address is Zitadel's verified `<username>@agentx.localhost`. */
    readonly firstAdmin: TestUser & { readonly totpSecret: string };
    /** As `totp`, invited by the first admin, then given another role and deactivated (B4-6d-2). */
    readonly member: TestUser & { readonly totpSecret: string };
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
  try {
    app.clientId = (await createOidcApp(client, projectId, run, REDIRECT_URI)).clientId;
    const noFactor = await createHumanUser(client, `${run}-nofactor`, password);
    created.push(noFactor);
    const withTotp = await createHumanUser(client, `${run}-totp`, password);
    created.push(withTotp);
    const totpSecret = await registerTotp(client, withTotp.userId);
    await verifyTotp(client, withTotp.userId, totp(totpSecret, Date.now()));
    const signIn = await createHumanUser(client, `${run}-signin`, password);
    created.push(signIn);
    const signInSecret = await registerTotp(client, signIn.userId);
    await verifyTotp(client, signIn.userId, totp(signInSecret, Date.now()));
    const stepUpApp = await createHumanUser(client, `${run}-stepup-app`, password);
    created.push(stepUpApp);
    const stepUpSecret = await registerTotp(client, stepUpApp.userId);
    await verifyTotp(client, stepUpApp.userId, totp(stepUpSecret, Date.now()));
    const stepUpKey = await createHumanUser(client, `${run}-stepup-key`, password);
    created.push(stepUpKey);
    const firstAdmin = await createHumanUser(client, `${run}-first-admin`, password);
    created.push(firstAdmin);
    const firstAdminSecret = await registerTotp(client, firstAdmin.userId);
    await verifyTotp(client, firstAdmin.userId, totp(firstAdminSecret, Date.now()));
    const member = await createHumanUser(client, `${run}-member`, password);
    created.push(member);
    const memberSecret = await registerTotp(client, member.userId);
    await verifyTotp(client, member.userId, totp(memberSecret, Date.now()));
    await loginSees(client, noFactor, ['AUTHENTICATION_METHOD_TYPE_PASSWORD']);
    await loginSees(client, stepUpKey, ['AUTHENTICATION_METHOD_TYPE_PASSWORD']);
    await loginSees(client, stepUpApp, ['AUTHENTICATION_METHOD_TYPE_PASSWORD', 'AUTHENTICATION_METHOD_TYPE_TOTP']);
    await loginSees(client, withTotp, ['AUTHENTICATION_METHOD_TYPE_PASSWORD', 'AUTHENTICATION_METHOD_TYPE_TOTP']);
    await loginSees(client, signIn, ['AUTHENTICATION_METHOD_TYPE_PASSWORD', 'AUTHENTICATION_METHOD_TYPE_TOTP']);
    await loginSees(client, firstAdmin, ['AUTHENTICATION_METHOD_TYPE_PASSWORD', 'AUTHENTICATION_METHOD_TYPE_TOTP']);
    await loginSees(client, member, ['AUTHENTICATION_METHOD_TYPE_PASSWORD', 'AUTHENTICATION_METHOD_TYPE_TOTP']);
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
        firstAdmin: { ...firstAdmin, totpSecret: firstAdminSecret },
        member: { ...member, totpSecret: memberSecret },
      },
      api,
      policy: await loginPolicy(client),
      impersonation: await impersonationEnabled(client),
    });
  } catch (error) {
    await Promise.allSettled([
      ...created.map((user) => deleteUser(client, user.userId)),
      deleteProject(client, app.projectId),
    ]);
    throw error;
  }

  return async () => {
    await Promise.allSettled([
      ...created.map((user) => deleteUser(client, user.userId)),
      deleteProject(client, app.projectId),
    ]);
  };
}
