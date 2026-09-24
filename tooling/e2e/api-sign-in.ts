// The API as the local login service's OIDC client (ADR-003 §5; B2-3b), for
// the sign-in tests. The stack starts with sign-in off; this registers the API
// with Zitadel as a confidential client, in a project of its own, writes its
// settings where compose reads them (secrets/api-sign-in.env, loaded by the
// API's `env_file`) and its secret into the folder mounted into the API alone
// (secrets/api-sign-in), then starts the API again with them, together with
// the relay that shares its network (compose.yaml, api-login-relay).
//
// The registration is the stack's, not the run's: a later run finds it (the
// client ID in the file still one of the project's apps) and keeps it, so it
// is made again only for a fresh stack. Staging does the same by hand (B2-6).
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import { API_ORIGIN, LOGIN_ORIGIN, restart, SECRETS_DIR } from './compose.ts';
import { clientIdsOf, createConfidentialApp, deleteProject, projectsNamed, type ZitadelClient } from './zitadel.ts';

/** The Zitadel project that holds the API's client. */
const PROJECT = 'Agent X API (local stack)';

/** Where the login service sends the browser back: the API's callback, as the browser reaches it. */
const API_REDIRECT_URI = `${API_ORIGIN}/v1/auth/callback`;

/** The settings file compose loads into the API, and the secret's file, which the API sees at SECRET_MOUNTED. */
const SETTINGS_FILE = path.join(SECRETS_DIR, 'api-sign-in.env');
const SECRET_FILE = path.join(SECRETS_DIR, 'api-sign-in', 'oidc-client-secret');
const SECRET_MOUNTED = '/mnt/sign-in/oidc-client-secret';

export interface ApiSignIn {
  readonly clientId: string;
  /** The client's secret, so a test can check it reaches no log. Never printed. */
  readonly clientSecret: string;
}

/** The registration the files hold, if both are there. */
function written(): ApiSignIn | undefined {
  try {
    const settings = readFileSync(SETTINGS_FILE, 'utf8');
    const clientId = /^AGENTX_OIDC_CLIENT_ID=(.+)$/m.exec(settings)?.[1]?.trim();
    const clientSecret = readFileSync(SECRET_FILE, 'utf8').trim();
    return clientId === undefined || clientSecret === '' ? undefined : { clientId, clientSecret };
  } catch {
    return undefined;
  }
}

/** The API's settings, one per line, as compose reads an env file. */
const settingsFor = (clientId: string): string =>
  [
    '# Written by the end-to-end suite (tooling/e2e/api-sign-in.ts): the API as the login service client.',
    `AGENTX_OIDC_ISSUER=${LOGIN_ORIGIN}`,
    `AGENTX_OIDC_CLIENT_ID=${clientId}`,
    `AGENTX_OIDC_CLIENT_SECRET_FILE=${SECRET_MOUNTED}`,
    `AGENTX_OUTBOUND_ALLOWED_ORIGINS=${LOGIN_ORIGIN}`,
    '',
  ].join(String.fromCharCode(10));

/**
 * Waits until the API answers through the edge: the edge looks the API's
 * address up again at most every ten seconds, so a new container can be
 * unreachable for that long after it is healthy.
 */
async function apiAnswers(timeoutMs = 60_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const status = await fetch(`${API_ORIGIN}/health`).then(
      (response) => response.status,
      () => 0,
    );
    if (status === 200) return;
    if (Date.now() > deadline)
      throw new Error(`the API did not answer through the edge after it restarted (${String(status)})`);
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
}

/**
 * Waits until Zitadel lists the new client: it keeps its apps in a table it
 * updates a moment after each change, as it does users (`loginSees`).
 */
async function clientListed(
  client: ZitadelClient,
  projectId: string,
  clientId: string,
  timeoutMs = 60_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!(await clientIdsOf(client, projectId)).includes(clientId)) {
    if (Date.now() > deadline)
      throw new Error(`Zitadel still doesn't list the API's client after ${String(timeoutMs)} ms`);
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
}

/** The API registered with the login service and running with sign-in on. */
export async function apiSignIn(client: ZitadelClient): Promise<ApiSignIn> {
  const projects = await projectsNamed(client, PROJECT);
  const current = written();
  if (current !== undefined && projects.length === 1) {
    const [projectId = ''] = projects;
    if ((await clientIdsOf(client, projectId)).includes(current.clientId)) {
      // Started with them already, unless the stack was started afresh since: then compose sees the change.
      await restart(['api', 'api-login-relay'], false);
      await apiAnswers();
      return current;
    }
  }

  await Promise.all(projects.map((projectId) => deleteProject(client, projectId)));
  const { id: projectId } = await client.post<{ id: string }>('/management/v1/projects', { name: PROJECT });
  const made = await createConfidentialApp(client, projectId, 'agentx-api', API_REDIRECT_URI);
  await clientListed(client, projectId, made.clientId);
  // Readable by the API, which runs as its own user with every capability dropped (as prepare's keys).
  writeFileSync(SECRET_FILE, made.clientSecret, { mode: 0o644 });
  writeFileSync(SETTINGS_FILE, settingsFor(made.clientId), { mode: 0o644 });
  // New containers: compose can't see a changed secret file, and the relay must join the new API's network.
  await restart(['api', 'api-login-relay'], true);
  await apiAnswers();
  return { clientId: made.clientId, clientSecret: made.clientSecret };
}
