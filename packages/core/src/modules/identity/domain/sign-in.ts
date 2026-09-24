// What a sign-in hands the identity module (ADR-003 §5): who the login service
// says the person is, and what it proved. The OIDC client (B2-2) takes these
// from an ID token it has already checked; this is the module's own check of
// their shape, so no caller can store what the table's limits would refuse
// halfway through a sign-in, or text a log or a header could read two ways.

/** Who a person is to the login service: its issuer, and the subject it gave them (OIDC's `iss` and `sub`). */
export interface Subject {
  readonly issuer: string;
  readonly subject: string;
}

/** What one sign-in proved, kept on the session as its evidence. */
export interface SignInEvidence {
  /** The login service's own session (OIDC's `sid`), where it gives one. */
  readonly idpSessionId: string | undefined;
  /** When the person authenticated (OIDC's `auth_time`). */
  readonly authTime: Date;
  /** How they authenticated (OIDC's `amr`, RFC 8176), such as `pwd`, `otp`, `mfa`. */
  readonly amr: readonly string[];
}

/** The sign-in's facts can't be taken; the message says which, never what it was. */
export class SignInRefused extends Error {
  override readonly name = 'SignInRefused';
}

/** Visible ASCII, `!` to `~`, 1 to 255 of them: OIDC's `sub` is ASCII, at most 255 characters. */
const VISIBLE = /^[!-~]{1,255}$/;
/** An authentication method's name: RFC 8176's are short lower-case words. */
const METHOD = /^[!-~]{1,32}$/;
/** The most methods one sign-in may name: the table's own limit. */
const MOST_METHODS = 16;

/** True when the value is text the pattern matches: a caller the compiler can't see could pass anything. */
const matches = (pattern: RegExp, value: unknown): boolean => typeof value === 'string' && pattern.test(value);

/** Throws SignInRefused unless the subject can be stored. */
export function checkSubject({ issuer, subject }: Subject): void {
  if (!matches(VISIBLE, issuer)) throw new SignInRefused('the issuer is not 1 to 255 visible ASCII characters');
  if (!matches(VISIBLE, subject)) throw new SignInRefused('the subject is not 1 to 255 visible ASCII characters');
}

/** Throws SignInRefused unless the evidence can be stored. */
export function checkEvidence({ idpSessionId, authTime, amr }: SignInEvidence): void {
  if (idpSessionId !== undefined && !matches(VISIBLE, idpSessionId)) {
    throw new SignInRefused("the login service's session ID is not 1 to 255 visible ASCII characters");
  }
  if (!(authTime instanceof Date) || Number.isNaN(authTime.getTime())) {
    throw new SignInRefused('the authentication time is not a valid date');
  }
  if (!Array.isArray(amr) || amr.length === 0 || amr.length > MOST_METHODS) {
    throw new SignInRefused(`the authentication methods are not a list of 1 to ${MOST_METHODS}`);
  }
  // Array.from makes a hole in a sparse list undefined, which every() would skip.
  if (!Array.from(amr).every((method) => matches(METHOD, method))) {
    throw new SignInRefused('an authentication method is not 1 to 32 visible ASCII characters');
  }
}

/**
 * Where a browser may be sent back to after signing in (SEC-WEB-04): a path
 * on our own origin, never another site. It starts with one `/` (two would
 * name another host, and a backslash is read as a slash by browsers), holds
 * only letters, digits and `-._~/%?=&`, and is at most 512 characters, so
 * nothing in it can end the Location header or reach another origin.
 */
// The class holds no backslash, so a second slash is the only way to another host.
const RETURN_PATH = /^\/(?!\/)[A-Za-z0-9\-._~/%?=&]{0,511}$/;

/** The path to send the browser to when it asks for none. */
export const HOME_PATH = '/';

/** True when the browser may be sent back to this path. */
export const isReturnPath = (value: unknown): value is string => typeof value === 'string' && RETURN_PATH.test(value);
