// The weekly certificate watch (decision 50; security-weekly.yml, "Staging's
// certificates last 30 more days"). Azure's managed certificates renew
// themselves, so long as each door's host keeps its DNS records and answers;
// this says so in time if one hasn't. It reads, with read rights alone (the
// infrastructure plan's identity, Reader on the resource group):
// - each door's managed certificate in Azure (certificates.bicep): there, and
//   provisioned (`Succeeded`), which a failed renewal or a lost validation is not
// - when it ends: Azure's own date where the certificate carries one, and
//   otherwise the end of the certificate the host serves (a TLS handshake with
//   the host Azure names), since Azure's managed certificates API gives no
//   expiry date today
// and fails, in plain words, on any certificate missing, not provisioned,
// unreadable, or with under 30 days left. A failed scheduled run emails the
// repository's owner; Incident-Response-Playbook section U says what to do.
//
//   node deploy/azure/certificate-watch.ts
//
// CI's log is public: a certificate is named by its resource name alone
// (mc-agentx-stg-app), never by its host, which names the domain.
import { connect } from 'node:tls';

import { ARM, type Az, armList, azJson, RESOURCE_GROUP, realAz, text } from './deploy.ts';

/** The API version the certificates are deployed with (certificates.bicep). */
const CERTIFICATES_API = '2026-01-01';

/** Each door's managed certificate (names.bicep `certificateName`), by the door it serves. */
export const DOOR_CERTIFICATES: Readonly<Record<string, string>> = {
  app: 'mc-agentx-stg-app',
  auth: 'mc-agentx-stg-auth',
};

/** Days a certificate must still have: Azure renews about 45 days before the end, so under 30 is a renewal missed. */
export const DAYS_LEFT = 30;

const DAY_MS = 86_400_000;

/** One managed certificate as Azure lists it: the fields read. */
export interface ManagedCertificate {
  readonly name: string;
  readonly host: string;
  readonly state: string;
  /** Azure's own end date, where the certificate carries one. */
  readonly expires?: string;
}

/** The end date of the certificate a host serves, or why it couldn't be read (never naming the host). */
export type ServedEnd = (host: string) => Promise<{ readonly ends: Date } | { readonly unreadable: string }>;

const WHAT_NEXT =
  "What next: check each host's A and asuid TXT records, then keep the apps answering (deploy.ts apps --keep-running) and run deploy.ts certificates; rerun this check (Incident-Response-Playbook section U).";

/** The environment's managed certificates, read through Azure Resource Manager. */
export function readCertificates(az: Az, subscription: string): ManagedCertificate[] {
  const url = `${ARM}subscriptions/${subscription}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.App/managedEnvironments/cae-agentx-staging/managedCertificates?api-version=${CERTIFICATES_API}`;
  return armList({ az }, url, "the environment's managed certificates").map((each) => {
    const read = each as {
      name?: unknown;
      properties?: { subjectName?: unknown; provisioningState?: unknown; expirationDate?: unknown };
    };
    const expires = text(read.properties?.expirationDate);
    return {
      name: text(read.name),
      host: text(read.properties?.subjectName),
      state: text(read.properties?.provisioningState),
      ...(expires === '' ? {} : { expires }),
    };
  });
}

/**
 * Each door's certificate in plain words, and whether all are sound: there, provisioned, its end readable, and at
 * least DAYS_LEFT days away.
 */
export async function checkCertificates(
  certificates: readonly ManagedCertificate[],
  served: ServedEnd,
  now: Date,
): Promise<{ readonly lines: string[]; readonly sound: boolean }> {
  const lines: string[] = [];
  let sound = true;
  const fail = (line: string): void => {
    lines.push(line);
    sound = false;
  };
  for (const [door, name] of Object.entries(DOOR_CERTIFICATES)) {
    const found = certificates.find((each) => each.name === name);
    if (found === undefined || found.host === '') {
      fail(`${name} (the ${door} door's) isn't in Azure, so its host serves no certificate Azure renews. ${WHAT_NEXT}`);
      continue;
    }
    if (found.state !== 'Succeeded') {
      fail(
        `${name} (the ${door} door's) is ${found.state || 'in no state Azure gives'}, not Succeeded: a renewal or its validation failed, and the certificate the host serves will run out. ${WHAT_NEXT}`,
      );
      continue;
    }
    const azureEnd = found.expires === undefined ? undefined : new Date(found.expires);
    const end =
      azureEnd !== undefined && !Number.isNaN(azureEnd.getTime()) ? { ends: azureEnd } : await served(found.host);
    if ('unreadable' in end) {
      fail(
        `${name} (the ${door} door's) is provisioned, but the certificate its host serves couldn't be read (${end.unreadable}): check the host answers. ${WHAT_NEXT}`,
      );
      continue;
    }
    const days = Math.floor((end.ends.getTime() - now.getTime()) / DAY_MS);
    const ends = end.ends.toISOString().slice(0, 10);
    if (days < DAYS_LEFT) {
      fail(
        `${name} (the ${door} door's) ends ${ends}, in ${String(days)} days: under ${String(DAYS_LEFT)}, so Azure hasn't renewed it and sign-in or the API stops answering over https when it ends. ${WHAT_NEXT}`,
      );
      continue;
    }
    lines.push(`${name} (the ${door} door's) is provisioned and ends ${ends}, in ${String(days)} days.`);
  }
  return { lines, sound };
}

/** The real handshake: the end of the certificate the host serves on 443, within 30 seconds. */
const servedEnd: ServedEnd = (host) =>
  new Promise((resolve) => {
    const socket = connect({ host, port: 443, servername: host, timeout: 30_000 }, () => {
      const validTo = socket.getPeerCertificate().valid_to;
      socket.end();
      const ends = new Date(validTo);
      resolve(Number.isNaN(ends.getTime()) ? { unreadable: 'it gave no end date' } : { ends });
    });
    socket.on('timeout', () => {
      socket.destroy();
      resolve({ unreadable: 'no answer within 30 seconds' });
    });
    // The error's message can name the host: only its code is said.
    socket.on('error', (error: NodeJS.ErrnoException) => {
      resolve({ unreadable: error.code ?? 'the connection failed' });
    });
  });

if (import.meta.main) {
  try {
    const az = realAz();
    const subscription = text((azJson(az, ['account', 'show']) as { id?: unknown }).id);
    const { lines, sound } = await checkCertificates(readCertificates(az, subscription), servedEnd, new Date());
    for (const line of lines) console.log(line);
    process.exitCode = sound ? 0 : 1;
  } catch {
    // Azure's message names the request's URL, and so the subscription: not repeated in the public log.
    console.log(
      "Staging's managed certificates could not be read from Azure, so nobody knows whether they renew. What next: rerun this workflow; if it fails again, check staging-whatif's sign-in (its Reader grant on the resource group).",
    );
    process.exitCode = 1;
  }
}
