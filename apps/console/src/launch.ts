// Whether Agent X is launched (partner S216): until it is, a visitor who is not
// signed in sees only the private way in, never the front page. Turning it on is
// a deliberate change, reviewed like any other, made only when the partner and
// Claude decide to launch.
// Widened to boolean, so the pages read it as the switch it is, not as a fixed `false`.
export const LAUNCHED = false as boolean;
