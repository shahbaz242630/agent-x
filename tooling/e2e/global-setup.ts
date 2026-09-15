// Vitest global setup for the end-to-end suite (vitest.e2e.config.ts): FX-IDP.
// With the compose stack up, it takes Zitadel's automation token out of the
// stack and provisions what the login tests need, named by this run: an OIDC
// client, a user with a password and no second factor, and a user with an
// authenticator app, then waits until the login can see both. It reads the
// policies the tests assert on. Teardown removes what it created.
import { randomBytes } from 'node:crypto';

import type { TestProject } from 'vitest/node';

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
  };
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
    await loginSees(client, noFactor, ['AUTHENTICATION_METHOD_TYPE_PASSWORD']);
    await loginSees(client, withTotp, ['AUTHENTICATION_METHOD_TYPE_PASSWORD', 'AUTHENTICATION_METHOD_TYPE_TOTP']);

    project.provide('e2e', {
      issuer: LOGIN_ORIGIN,
      clientId: app.clientId,
      redirectUri: REDIRECT_URI,
      password,
      users: { noFactor, totp: { ...withTotp, totpSecret } },
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
