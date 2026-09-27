// The API as the local login service's OIDC client (ADR-003 §5; B2-3b), for
// the sign-in tests. The stack starts with sign-in off; this registers the API
// with Zitadel as a confidential client, in a project of its own, writes its
// settings where compose reads them (secrets/api-sign-in.env, loaded by the
// API's `env_file`) and its secret into the folder mounted into the API alone
// (secrets/api-sign-in), then starts the API again with them. The API calls
// Zitadel by its name on the stack's network, naming the issuer's host in
// Zitadel's own headers (AGENTX_OIDC_INTERNAL_ORIGIN, B2-6), as staging's does.
//
// It also turns the API's email on (B6-2c), as on staging (B5-3): the login
// service's read-only service user `agentx-directory`, with the two roles it
// holds there once the partner gives the second (Org Owner Viewer, and IAM
// Owner Viewer for the event feed), its token beside the client's secret; and
// an access key for the stand-in email service (deploy/compose/mail-sink.ts),
// one copy for the API and one in the service's own folder.
//
// The registration is the stack's, not the run's: a later run finds it (the
// client ID in the file still one of the project's apps; the token still
// reading the feed) and keeps it, so it is made again only for a fresh stack.
// Staging does the same by hand (B2-6, B5-3).
import { randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import { API_ORIGIN, LOGIN_ORIGIN, restart, SECRETS_DIR } from './compose.ts';
import {
  clientIdsOf,
  createConfidentialApp,
  createServiceUser,
  deleteProject,
  deleteUser,
  grantInstanceRoles,
  grantOrgRoles,
  projectsNamed,
  usersNamed,
  zitadelClient,
  type ZitadelClient,
} from './zitadel.ts';

/** The Zitadel project that holds the API's client. */
const PROJECT = 'Agent X API (local stack)';

/** Where the login service sends the browser back: the API's callback, as the browser reaches it. */
const API_REDIRECT_URI = `${API_ORIGIN}/v1/auth/callback`;

/** Zitadel as the API reaches it on the stack's network: the login pages' own way there. */
const LOGIN_SERVICE_INTERNAL = 'http://zitadel:8080';

/** The settings file compose loads into the API, and the secret's file, which the API sees at SECRET_MOUNTED. */
const SETTINGS_FILE = path.join(SECRETS_DIR, 'api-sign-in.env');
const SECRET_FILE = path.join(SECRETS_DIR, 'api-sign-in', 'oidc-client-secret');
const SECRET_MOUNTED = '/mnt/sign-in/oidc-client-secret';

/** The service user the API reads addresses and the event feed as, named as on staging. */
const DIRECTORY_USER = 'agentx-directory';

/** Its token, and the email access key, beside the client's secret; the key's copy in the stand-in's folder. */
const TOKEN_FILE = path.join(SECRETS_DIR, 'api-sign-in', 'directory-token');
const TOKEN_MOUNTED = '/mnt/sign-in/directory-token';
const EMAIL_KEY_FILE = path.join(SECRETS_DIR, 'api-sign-in', 'email-access-key');
const EMAIL_KEY_MOUNTED = '/mnt/sign-in/email-access-key';
const SINK_KEY_FILE = path.join(SECRETS_DIR, 'mail-sink', 'access-key');

/** The stand-in email service, as the API reaches it on the stack's network (compose.yaml's `mail`). */
const MAIL_ORIGIN = 'http://mail:8080';

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
    `AGENTX_OIDC_INTERNAL_ORIGIN=${LOGIN_SERVICE_INTERNAL}`,
    `AGENTX_OUTBOUND_ALLOWED_ORIGINS=${LOGIN_SERVICE_INTERNAL},${MAIL_ORIGIN}`,
    `AGENTX_EMAIL_ENDPOINT=${MAIL_ORIGIN}`,
    'AGENTX_EMAIL_SENDER=DoNotReply@agentx.localhost',
    `AGENTX_EMAIL_ACCESS_KEY_FILE=${EMAIL_KEY_MOUNTED}`,
    `AGENTX_DIRECTORY_TOKEN_FILE=${TOKEN_MOUNTED}`,
    '',
  ].join(String.fromCharCode(10));

/**
 * Waits until the API answers through the edge: the edge looks the API's
 * address up again at most every ten seconds, so a new container can be
 * unreachable for that long after it is healthy.
 */
export async function apiAnswers(timeoutMs = 60_000): Promise<void> {
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

/** A file's text, or undefined when it isn't there. */
function textOf(file: string): string | undefined {
  try {
    return readFileSync(file, 'utf8').trim();
  } catch {
    return undefined;
  }
}

/**
 * Whether the token can do both things the API asks of it: read a person (the
 * address book, B5-3) and read the event feed (B6-2b), which IAM Owner Viewer
 * gives. Zitadel grants a role a moment after it records it, so a new token is
 * asked again until it can.
 */
async function directoryReads(token: string, userId: string): Promise<boolean> {
  const directory = zitadelClient(LOGIN_ORIGIN, token);
  try {
    await directory.get(`/v2/users/${userId}`);
    await directory.post('/admin/v1/events/_search', { limit: 1 });
    return true;
  } catch {
    return false;
  }
}

/** The directory's token and the email key, kept if they still work; true if they were made afresh. */
async function apiEmail(client: ZitadelClient): Promise<boolean> {
  const token = textOf(TOKEN_FILE);
  const key = textOf(EMAIL_KEY_FILE);
  const found = await usersNamed(client, DIRECTORY_USER);
  const [userId] = found;
  if (
    token !== undefined &&
    key !== undefined &&
    key === textOf(SINK_KEY_FILE) &&
    found.length === 1 &&
    userId !== undefined &&
    (await directoryReads(token, userId))
  ) {
    return false;
  }

  await Promise.all(found.map((id) => deleteUser(client, id)));
  const made = await createServiceUser(client, DIRECTORY_USER, 'Agent X directory (local stack)');
  await grantOrgRoles(client, made.userId, ['ORG_OWNER_VIEWER']);
  await grantInstanceRoles(client, made.userId, ['IAM_OWNER_VIEWER']);
  const deadline = Date.now() + 60_000;
  while (!(await directoryReads(made.token, made.userId))) {
    if (Date.now() > deadline) throw new Error("the directory's token still can't read a user and the event feed");
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  // An access key as ACS gives them, in base64. Readable by the API's and the stand-in's own users.
  const accessKey = randomBytes(32).toString('base64');
  writeFileSync(TOKEN_FILE, made.token, { mode: 0o644 });
  writeFileSync(EMAIL_KEY_FILE, accessKey, { mode: 0o644 });
  writeFileSync(SINK_KEY_FILE, accessKey, { mode: 0o644 });
  return true;
}

/** The API's client with the login service: the one the files name if it is still there, else a new one. */
async function apiClient(client: ZitadelClient): Promise<ApiSignIn & { made: boolean }> {
  const projects = await projectsNamed(client, PROJECT);
  const current = written();
  if (current !== undefined && projects.length === 1) {
    const [projectId = ''] = projects;
    if ((await clientIdsOf(client, projectId)).includes(current.clientId)) return { ...current, made: false };
  }

  await Promise.all(projects.map((projectId) => deleteProject(client, projectId)));
  const { id: projectId } = await client.post<{ id: string }>('/management/v1/projects', { name: PROJECT });
  const made = await createConfidentialApp(client, projectId, 'agentx-api', API_REDIRECT_URI);
  await clientListed(client, projectId, made.clientId);
  // Readable by the API, which runs as its own user with every capability dropped (as prepare's keys).
  writeFileSync(SECRET_FILE, made.clientSecret, { mode: 0o644 });
  return { clientId: made.clientId, clientSecret: made.clientSecret, made: true };
}

/** The API registered with the login service and running with sign-in and email on. */
export async function apiSignIn(client: ZitadelClient): Promise<ApiSignIn> {
  const { clientId, clientSecret, made } = await apiClient(client);
  const emailMade = await apiEmail(client);
  writeFileSync(SETTINGS_FILE, settingsFor(clientId), { mode: 0o644 });
  // A new container when a secret file changed, which compose can't see; otherwise compose makes
  // one only if the settings changed (this file, or a stack started afresh since).
  await restart(['api'], made || emailMade);
  await apiAnswers();
  return { clientId, clientSecret };
}
