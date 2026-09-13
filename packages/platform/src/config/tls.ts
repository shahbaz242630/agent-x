// SEC-PTR-07 (ADR-012 §6): the app never runs with TLS certificate checks off.
// Node turns them off for every connection when this variable is exactly '0',
// and it reads the variable afresh on each new connection. So the start-up
// check refuses it, lint stops our code touching process.env, and the outbound
// client checks again before every request, because a dependency could still
// change it after start-up.
const TLS_CHECKS_OFF_SWITCH = 'NODE_TLS_REJECT_UNAUTHORIZED';

type Env = Readonly<Record<string, string | undefined>>;

/**
 * Any value but '1' is refused, not only '0': a value there means someone
 * meant to change TLS checking.
 */
export function tlsProblems(env: Env): string[] {
  const value = env[TLS_CHECKS_OFF_SWITCH];
  return value === undefined || value === '1'
    ? []
    : [`${TLS_CHECKS_OFF_SWITCH}: must be unset (or 1); 0 turns off TLS certificate checks for every connection`];
}

/** For the check before each outbound request, which reads the live environment. */
export function tlsChecksOff(env: Env = process.env): boolean {
  return tlsProblems(env).length > 0;
}
