// The console watch (PL-26): Zitadel's console on the auth host is opened for a
// piece of work and closed straight after (deploy.ts console --open, --close),
// so an open one left behind must be seen. Every few hours console-watch.yml
// reads the auth door, with read rights alone (the infrastructure plan's
// identity, Reader on the resource group), and fails while the console is open
// or the door is in neither of auth-door.json's two shapes: a failed scheduled
// run emails the repository's owner. The infrastructure plan says the same on
// every merge (infra.ts), without failing for an open console.
//
//   node deploy/azure/console-watch.ts
//
// Only the door's shape is printed: never its host, which names the domain in
// CI's public log.
import type { DoorShape } from './auth-door.ts';
import { type Az, azJson, CONSOLE_SAID, readConsoleDoor, realAz, text } from './deploy.ts';

/**
 * Reads the auth door and says what its shape means: its shape (undefined: neither), and 1 when it is in neither
 * shape, or when the console is reachable (open, or the pre-PL-26 legacy door) and `openIsRed` (the watch); otherwise 0.
 */
export function checkConsoleDoor(
  az: Az,
  subscription: string,
  say: (line: string) => void,
  openIsRed: boolean,
): { readonly status: number; readonly shape: DoorShape | undefined } {
  const { state } = readConsoleDoor(az, subscription);
  say(CONSOLE_SAID[state ?? 'neither']);
  return { status: state === undefined || (state !== 'closed' && openIsRed) ? 1 : 0, shape: state };
}

if (import.meta.main) {
  const az = realAz();
  const subscription = text((azJson(az, ['account', 'show']) as { id?: unknown }).id);
  try {
    process.exitCode = checkConsoleDoor(
      az,
      subscription,
      (line) => {
        console.log(line);
      },
      true,
    ).status;
  } catch {
    // Azure's message names the request's URL, and so the subscription: not repeated in the public log.
    console.log(
      "The auth host's door could not be read, so nobody knows whether Zitadel's console is open. What next: re-run this workflow; if it fails again, check staging-whatif's sign-in (its Reader grant on the resource group) and run deploy.ts console --status by hand.",
    );
    process.exitCode = 1;
  }
}
