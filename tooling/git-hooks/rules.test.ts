import { describe, expect, it } from 'vitest';

import { describeProblem, entropy, lineProblems, pathProblems, type RuleId, textProblems } from './rules.ts';

// Every sample that must be caught is assembled when the test runs, so this
// file holds nothing the secret scanners (or these rules, run over the
// repository in CI) would report.
const q = String.fromCharCode(39);
const join = (...parts: string[]): string => parts.join('');

const rulesOf = (file: string, text: string): RuleId[] => lineProblems(file, 1, text).map((problem) => problem.rule);

describe('files that must never be committed', () => {
  it.each([
    ['Documents/Master-Handoff.md'],
    ['Documents'],
    ['.env'],
    ['deploy/compose/.env'],
    ['.env.local'],
    ['config/.env.production'],
    ['certs/server.pem'],
    ['keys/signing.key'],
    ['store.p12'],
    ['store.PFX'],
    ['release.jks'],
    ['android.keystore'],
    ['pat-automation/automation.pat'],
    ['id_rsa'],
    ['home/.ssh/id_ed25519'],
    ['DOCUMENTS/notes.md'],
    ['config/.ENV'],
    ['corepack.cmd'],
    ['git.exe'],
    ['node.bat'],
    ['GITLEAKS'],
    ['corepack.js'],
  ])('refuses %s', (file) => {
    expect(pathProblems(file).map((problem) => problem.rule)).toEqual(['forbidden-file']);
  });

  it.each([
    ['.env.example'],
    ['docs/Documents.md'],
    ['deploy/compose/prepare.ts'],
    ['tooling/e2e/env.ts'],
    ['id_rsa.pub'],
    ['keys/README.md'],
    ['monkey.ts'],
    ['.ENV.example'],
    ['pnpm-lock.yaml'],
    ['pnpm-workspace.yaml'],
    ['tooling/git-hooks/gitleaks.ts'],
    ['scripts/node.mjs'],
  ])('allows %s', (file) => {
    expect(pathProblems(file)).toEqual([]);
  });
});

describe('secrets in a line', () => {
  it('finds a private key block', () => {
    expect(rulesOf('a.txt', join('-'.repeat(5), 'BEGIN RSA PRIVATE KEY', '-'.repeat(5)))).toEqual(['private-key']);
    expect(rulesOf('a.txt', join('-'.repeat(5), 'BEGIN PRIVATE KEY', '-'.repeat(5)))).toEqual(['private-key']);
    expect(rulesOf('a.txt', join('-'.repeat(5), 'BEGIN PGP PRIVATE KEY BLOCK', '-'.repeat(5)))).toEqual([
      'private-key',
    ]);
    expect(rulesOf('a.txt', join('-'.repeat(5), 'BEGIN PUBLIC KEY', '-'.repeat(5)))).toEqual([]);
  });

  it.each([
    ['a GitHub token', join('gh', 'p_', 'A1b2'.repeat(9))],
    ['a GitHub fine-grained token', join('github', '_pat_', 'a1B2_'.repeat(17))],
    ['an AWS access key', join('AK', 'IA', 'Q2W3E4R5T6Y7U8I9')],
    ['a Google API key', join('AI', 'za', 'x'.repeat(35))],
    ['a Slack token', join('xo', 'xb-', '1234567890-abcdef')],
    ['a Stripe live key', join('sk', '_live_', 'a1'.repeat(12))],
    ['an npm token', join('np', 'm_', 'a1B2'.repeat(9))],
    ['an Azure storage key', join('Account', 'Key=', 'Ab1/'.repeat(11), '==')],
    ['a JSON web token', join('ey', 'J', 'a'.repeat(12), '.ey', 'J', 'b'.repeat(12), '.', 'c'.repeat(12))],
  ])('finds %s', (_name, token) => {
    expect(rulesOf('a.ts', `const value = ${q}${token}${q};`)).toEqual(['provider-token']);
  });

  it('leaves lookalikes alone', () => {
    expect(rulesOf('a.ts', join('gh', 'p_', 'short'))).toEqual([]);
    expect(rulesOf('a.ts', 'AKIAlowercase0000000000')).toEqual([]);
    expect(rulesOf('a.ts', 'const header = "eyJ";')).toEqual([]);
    expect(
      rulesOf('pnpm-lock.yaml', '    resolution: {integrity: sha512-Zm9vYmFyYmF6cXV4cXV1eHF1dXhxdXV4cXV1eA==}'),
    ).toEqual([]);
  });
});

describe('text the secret scanners mistake for a secret', () => {
  it.each([
    [
      'a test vector named as a secret (PR #15)',
      join('const RFC_', 'SECRET_BASE32 = ', q, 'GEZDGNBV', 'GY3TQOJQ', 'GEZDGNBV', 'GY3TQOJQ', q, ';'),
    ],
    ['a random test value named as a token', join('const TEST_', 'TOKEN = ', q, 'a1b2c3d4', 'e5f6g7h8', q, ';')],
    ['an object key', join('  api', 'Key: ', q, 'k3Jd92n', 'fKq01ZxP', q, ',')],
    ['a backtick literal', join('const pass', 'word = `', 'Zq81mV', 'n02kLp', '`;')],
    [
      'a camelCase variable in a password-named key (PR #23)',
      join('    AGENTX_DB_ZITADEL_PASS', 'WORD: zitadel', 'Login,'),
    ],
    ['a camelCase variable as an object password', join('  { user: x, pass', 'word: zitadel', 'Login }')],
    ['a dotted path that names no secret (PR #24)', join('    AGENTX_DB_ZITADEL_PASS', 'WORD: zitadel.', 'login,')],
    [
      'a list of readers under a quoted password key (PR #27)',
      join('  ', q, 'zitadel-admin-pass', 'word', q, ': [', q, 'zitadel-', 'setup', q, '],'),
    ],
    ['a word under a double-quoted password key', join('  "db_pass', 'word": "some-', 'thing-long",')],
    [
      'a call named for a secret given a name with a digit (PRs #66, #67)',
      join('    const auditMac = SEC', 'RET(', q, 'key-audit-', 'mac-v1', q, ');'),
    ],
    ['the same in lower case', join('pick(sec', 'ret(', q, 'db-', '2', q, '));')],
    [
      'a quoted reader keying a list of password-named secrets (PR #28)',
      join('  ', q, 'zitadel-init', q, ': [', q, 'db-zitadel-pass', 'word', q, '],'),
    ],
    [
      'the password-named secret later in the list',
      join(
        '  ',
        q,
        'zitadel-setup',
        q,
        ': [',
        q,
        'zitadel-masterkey',
        q,
        ', ',
        q,
        'zitadel-admin-pass',
        'word',
        q,
        '],',
      ),
    ],
  ])('finds %s', (_name, line) => {
    expect(rulesOf('a.test.ts', line)).toEqual(['scanner-bait']);
  });

  it.each([
    ['an environment reference', join('  pass', 'word: ', q, '${DB_PASS}', q, ',')],
    ['a plain word', join('const token', 'Type = ', q, 'Bearer', q, ';')],
    ['a constant label', join('accessToken', 'Type: ', q, 'OIDC_TOKEN_TYPE_BEARER', q, ',')],
    ['a psql variable', "ALTER ROLE agentx_owner PASSWORD :'owner_login';"],
    ['a dotted path that names the secret', join('    AGENTX_DB_ZITADEL_PASS', 'WORD: zitadelRole.pass', 'word,')],
    ['a call in a password-named key', join('    pass', "word: loginOf('owner'),")],
    ['a variable named for the secret it holds', join('    admin', 'Password: postgresAdmin', 'Password')],
    ['a name in capitals', join('    AGENTX_DB_PASS', 'WORD: MISPLACED,')],
    ['a type', join('  readonly pass', 'word: string;')],
    ['the path of a mounted file', join('AGENTX_DB_PASS', 'WORD_FILE: appFile,')],
    ['a redaction marker', join('secret: ', q, '[redacted]', q, ',')],
    ['a short value', join('const token = ', q, 'a1b2', q, ';')],
    ['a value with no digits', join('const secret = ', q, 'abcdefgh', 'ijklmnop', q, ';')],
    ['a repeated value', join('const secret = ', q, 'a1a1a1a1a1a1', q, ';')],
    ['a pairing written as one string', join('  ', q, 'zitadel-setup reads zitadel-admin-pass', 'word', q, ',')],
    ['a short unquoted key', join('  api: [', q, 'db-app-pass', 'word', q, '],')],
    [
      'a word and a password-named name not paired by a colon',
      join('READS(', q, 'migrate', q, ', ', q, 'db-owner-pass', 'word', q, ')'),
    ],
    ['a short word under a quoted password key', join('  ', q, 'pass', 'word', q, ': ', q, 'none', q, ',')],
    [
      'a call named for a secret given a name without a digit',
      join('    SEC', 'RET(', q, 'db-app-pass', 'word', q, '),'),
    ],
    [
      'a call named for a secret given a name built when the test runs',
      join('    SEC', 'RET(keyNamed(', q, 'audit-mac', q, ')),'),
    ],
    ['a reference under a quoted password key', join('  ', q, 'pass', 'word', q, ': ', q, '${DB_PASS}', q, ',')],
  ])('leaves alone %s', (_name, line) => {
    expect(rulesOf('a.ts', line)).toEqual([]);
  });

  it('asks for bare required-variable placeholders in YAML only (PR #16)', () => {
    const withMessage = join('      image: ', '$', '{TAG:?set the tag first}');
    expect(rulesOf('deploy/compose/compose.yaml', withMessage)).toEqual(['placeholder-message']);
    expect(rulesOf('.github/workflows/ci.yml', withMessage)).toEqual(['placeholder-message']);
    expect(rulesOf('deploy/compose/compose.yaml', join('      image: ', '$', '{TAG:?}'))).toEqual([]);
    expect(rulesOf('scripts/example.sh', withMessage)).toEqual([]);
  });
});

describe('invisible characters (S5)', () => {
  it.each([
    [0xa0, 'U+00A0'],
    [0xad, 'U+00AD'],
    [0x200b, 'U+200B'],
    [0x2028, 'U+2028'],
    [0x202e, 'U+202E'],
    [0xfeff, 'U+FEFF'],
    [0x07, 'U+0007'],
    [0x85, 'U+0085'],
    [0xe0041, 'U+E0041'],
  ])('finds code point %i and names it %s', (codePoint, name) => {
    const problems = lineProblems('a.ts', 3, `const a = 1;${String.fromCodePoint(codePoint)}`);
    expect(problems).toHaveLength(1);
    expect(problems[0]).toMatchObject({ rule: 'invisible-character', line: 3 });
    expect(problems[0]?.message).toContain(name);
  });

  it('allows tabs, carriage returns and ordinary text in any script', () => {
    const tab = String.fromCharCode(9);
    const carriageReturn = String.fromCharCode(13);
    expect(lineProblems('a.ts', 1, `${tab}const a = 1;${carriageReturn}`)).toEqual([]);
    // An em dash, an approximately-equal sign, a middle dot, an emoji and Arabic letters: visible, so fine.
    const ordinary = String.fromCodePoint(
      0x2014,
      0x20,
      0x2248,
      0x20,
      0xb7,
      0x20,
      0x1f44d,
      0x20,
      0x645,
      0x631,
      0x62d,
      0x628,
      0x627,
    );
    expect(lineProblems('a.md', 1, `Agent X ${ordinary}`)).toEqual([]);
  });
});

describe('reporting', () => {
  it('reports every problem in a file with its line, and never the matched text', () => {
    const token = join('gh', 'p_', 'A1b2'.repeat(9));
    const text = ['fine', `const value = ${q}${token}${q};`, `x${String.fromCharCode(0x200b)}`].join('\n');
    const problems = textProblems('src/a.ts', text);
    expect(problems.map((problem) => [problem.rule, problem.line])).toEqual([
      ['provider-token', 2],
      ['invisible-character', 3],
    ]);
    const lines = problems.map(describeProblem);
    expect(lines[0]).toBe('src/a.ts:2 [provider-token] looks like a GitHub token');
    expect(lines.join('\n')).not.toContain(token);
    expect(describeProblem(pathProblems('.env')[0] ?? { rule: 'forbidden-file', file: '', message: '' })).toBe(
      '.env [forbidden-file] an env file holds local secrets',
    );
  });

  it('measures entropy in bits per character', () => {
    expect(entropy('aaaa')).toBe(0);
    expect(entropy('abab')).toBe(1);
    expect(entropy('abcd')).toBe(2);
  });
});
