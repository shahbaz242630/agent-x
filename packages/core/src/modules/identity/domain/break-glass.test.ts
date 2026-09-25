// B4-6c: the login service's break-glass admin, known by its login name.
import { describe, expect, it } from 'vitest';

import { isBreakGlassLogin } from './break-glass.ts';

const ISSUER = 'https://auth.example.test';

describe('B4-6c the break-glass admin, by its login name', () => {
  it.each([
    ['with the first organisation’s domain', 'admin@agent-x.auth.example.test'],
    ['in another case', 'Admin@Agent-X.Auth.Example.Test'],
  ])('is the break-glass admin %s', (_what, loginName) => {
    expect(isBreakGlassLogin(loginName, ISSUER)).toBe(true);
  });

  it('reads the host of an issuer written in capitals in lower case', () => {
    expect(isBreakGlassLogin('admin@agent-x.auth.example.test', 'https://Auth.Example.TEST')).toBe(true);
  });

  it('reads the host from an issuer with a port and a path, as the compose stack’s', () => {
    expect(isBreakGlassLogin('admin@agent-x.localhost', 'http://localhost:8081/oauth')).toBe(true);
  });

  it.each([
    ['a person in the same organisation', 'shahbaz@agent-x.auth.example.test'],
    ['an admin in another organisation', 'admin@acme.auth.example.test'],
    ['the first organisation at another host', 'admin@agent-x.auth.elsewhere.test'],
    ['the first organisation’s domain one level down', 'admin@x.agent-x.auth.example.test'],
    ['a person whose username is the username alone', 'admin'],
    ['the same, in capitals', 'ADMIN'],
    ['the username with a suffix', 'admin2'],
    ['the login name with more after it', 'admin@agent-x.auth.example.test.evil.test'],
    ['the username as an email address elsewhere', 'admin@example.test'],
    ['empty', ''],
  ])('is not %s', (_what, loginName) => {
    expect(isBreakGlassLogin(loginName, ISSUER)).toBe(false);
  });

  it.each([undefined, null, 42, ['admin'], { name: 'admin' }])('is not %j, which isn’t text', (loginName) => {
    expect(isBreakGlassLogin(loginName, ISSUER)).toBe(false);
  });
});
