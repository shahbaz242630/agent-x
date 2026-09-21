// Lint rules for the whole repository (Rule Book §5, §7, §8). Every rule we add
// or tighten below has a broken snippet in tooling/gate-proofs/lint.test.ts
// that must keep failing.
import comments from '@eslint-community/eslint-plugin-eslint-comments/configs';
import eslint from '@eslint/js';
import { defineConfig, globalIgnores } from 'eslint/config';
import globals from 'globals';
import tseslint from 'typescript-eslint';

import { AUTHORITY_TABLES } from './tooling/authority-tables.ts';
import authorityTablesThroughSignedState from './tooling/eslint-rules/authority-tables-through-signed-state.js';
import noStringBuiltSql from './tooling/eslint-rules/no-string-built-sql.js';
import signedStateStepsInAuditModule from './tooling/eslint-rules/signed-state-steps-in-audit-module.js';
import tenantSettingOnlyInWithTenant from './tooling/eslint-rules/tenant-setting-only-in-with-tenant.js';

/**
 * A3c, ADR-012 §2: the authority tables, from the same registry the CI schema
 * checks read (tooling/authority-tables.ts, which takes the product's own list,
 * the one the API's live schema guard reads), so they can never drift. Node
 * strips the types as it loads it, which is why a plain JS config can import a
 * TypeScript file. Empty until slice B1 brings the first authority table; the
 * rule is proven on a registry of its own meanwhile
 * (tooling/gate-proofs/lint-authority-registry.test.ts).
 */
const authorityTables = AUTHORITY_TABLES.map(({ table, subject }) => ({ table, subject }));

/** SEC-WEB-03: nothing may write raw HTML into the page. */
const rawHtmlInjection = [
  {
    selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
    message: 'SEC-WEB-03: raw HTML injection is banned. Render text through React instead.',
  },
  {
    selector: 'AssignmentExpression > MemberExpression.left[property.name=/^(innerHTML|outerHTML|srcdoc)$/]',
    message: 'SEC-WEB-03: raw HTML injection is banned. Set textContent instead.',
  },
  {
    selector:
      'CallExpression[callee.property.name=/^(insertAdjacentHTML|createContextualFragment|setHTMLUnsafe|parseHTMLUnsafe)$/]',
    message: 'SEC-WEB-03: raw HTML injection is banned.',
  },
  {
    selector: "CallExpression[callee.object.name='document'][callee.property.name=/^write(ln)?$/]",
    message: 'SEC-WEB-03: document.write is banned.',
  },
];

/**
 * ADR-006 §3: business code reads the time only through the injected Clock.
 * Building a Date from a known value (`new Date(ms)`) stays allowed.
 */
const wallClock = [
  {
    selector: "NewExpression[callee.name='Date'][arguments.length=0]",
    message: 'ADR-006: read business time from the injected Clock, not new Date().',
  },
  {
    selector: "CallExpression[callee.name='Date']",
    message: 'ADR-006: read business time from the injected Clock, not Date().',
  },
  {
    selector: "CallExpression[callee.object.name='Date'][callee.property.name='now']",
    message: 'ADR-006: read business time from the injected Clock, not Date.now().',
  },
  {
    selector: "MemberExpression[object.name='globalThis'][property.name='Date']",
    message: 'ADR-006: read business time from the injected Clock, not globalThis.Date.',
  },
];

/**
 * SEC-PTR-07 (ADR-012 §6): product code never turns off TLS certificate checks.
 * The start-up config check covers the environment variable; these cover code.
 */
const tlsChecksOff = [
  {
    selector:
      "ObjectExpression > Property[key.name='rejectUnauthorized']:not([value.value=true]), " +
      "ObjectExpression > Property[key.value='rejectUnauthorized']:not([value.value=true]), " +
      "PropertyDefinition[key.name='rejectUnauthorized']:not([value.value=true])",
    message: 'SEC-PTR-07: TLS certificate checks stay on. Leave rejectUnauthorized out, or set it to true.',
  },
  {
    selector:
      "AssignmentExpression > MemberExpression.left[property.name='rejectUnauthorized'], " +
      "AssignmentExpression > MemberExpression.left[property.value='rejectUnauthorized']",
    message: 'SEC-PTR-07: TLS certificate checks stay on. Never assign rejectUnauthorized.',
  },
  {
    selector:
      "ObjectExpression > Property[key.name='checkServerIdentity'], " +
      "ObjectExpression > Property[key.value='checkServerIdentity'], " +
      "PropertyDefinition[key.name='checkServerIdentity'], " +
      "AssignmentExpression > MemberExpression.left[property.name='checkServerIdentity'], " +
      "AssignmentExpression > MemberExpression.left[property.value='checkServerIdentity']",
    message: 'SEC-PTR-07: a custom checkServerIdentity can skip the host name check. Keep the default.',
  },
];

/**
 * SEC-EVD-06: a reason code is a registered one, checked by the compiler. A
 * type assertion into a reason-code type (one code, a list of codes, or
 * `keyof typeof REASON_CODES`) would let an unregistered code through. Types
 * that merely mention a code, such as `Record<ReasonCode, number>`, are fine.
 */
const assertion = ':matches(TSAsExpression, TSTypeAssertion)';
const reasonCodeAssertions = [
  {
    selector: [
      `${assertion} > TSTypeReference.typeAnnotation[typeName.name='ReasonCode']`,
      `${assertion} > TSArrayType.typeAnnotation > TSTypeReference[typeName.name='ReasonCode']`,
      `${assertion} > TSTypeOperator.typeAnnotation > TSArrayType > TSTypeReference[typeName.name='ReasonCode']`,
      `${assertion} > TSTypeOperator.typeAnnotation[operator='keyof'] > TSTypeQuery[exprName.name='REASON_CODES']`,
    ].join(', '),
    message: 'SEC-EVD-06: never assert a value into a reason code. Use a code from REASON_CODES, or register one.',
  },
];

/** Rule Book §4, §5: settings come only from the checked config, read once at start-up. */
const configOnly = 'Read settings through loadConfig in @agentx/platform/config, which checks them at start-up.';

/** SEC-WEB-05: outbound HTTP goes only through the allowlisted client. */
const outboundOnly = 'SEC-WEB-05: make outbound requests with createOutboundFetch from @agentx/platform/outbound.';

/** The network globals Node provides (fetch and WebSocket), taken out of the global object by destructuring. */
const networkDestructuring = [
  {
    selector:
      'VariableDeclarator[init.name=/^(?:globalThis|global)$/] > ObjectPattern > Property[key.name=/^(?:fetch|WebSocket)$/]',
    message: outboundOnly,
  },
];

/** `process.env` reached through the global object, which the property rule below can't see. */
const environmentThroughGlobal = [
  { selector: "MemberExpression[property.name='env'][object.property.name='process']", message: configOnly },
];

/**
 * Rule Book §8, ADR-013: logs leave only through the logger, which redacts
 * every line. Writing to stdout or stderr any other way would skip that. The
 * logger itself writes to file descriptor 1 through pino, so it needs no
 * exception. Lint catches the direct spellings; the output guard
 * (guardOutputs, installed at start-up) cleans whatever else reaches the two
 * streams at run time.
 */
const loggerOnly = 'ADR-013: write logs with createLogger from @agentx/platform/observability, which redacts them.';
const outputStreams = ['stdout', 'stderr', '_rawDebug', 'report'].map((property) => ({
  object: 'process',
  property,
  message: loggerOnly,
}));
const outputBypasses = [
  {
    selector: "MemberExpression[property.name=/^(?:stdout|stderr)$/][object.property.name='process']",
    message: loggerOnly,
  },
  { selector: "MemberExpression[object.name=/^(?:globalThis|global)$/][property.name='console']", message: loggerOnly },
  // Writing to file descriptor 1 or 2, or to their device files, is writing to stdout or stderr.
  ...[1, 2].flatMap((descriptor) => [
    {
      selector: `CallExpression[callee.property.name=/^(?:write|writeSync|writeFileSync|appendFileSync)$/][arguments.0.value=${descriptor}]`,
      message: loggerOnly,
    },
    {
      selector: `CallExpression[callee.name=/^(?:write|writeSync|writeFileSync|appendFileSync)$/][arguments.0.value=${descriptor}]`,
      message: loggerOnly,
    },
  ]),
  { selector: "CallExpression[callee.name='createWriteStream'] Property[key.name='fd']", message: loggerOnly },
  { selector: "CallExpression[callee.property.name='createWriteStream'] Property[key.name='fd']", message: loggerOnly },
  { selector: 'Literal[value=/^\\/dev\\/(?:stdout|stderr|fd\\/[12])$/]', message: loggerOnly },
];

/** ADR-013: pino writes only to stdout; a transport or a multistream would send logs somewhere else. */
const pinoOnlyToStdout = 'ADR-013: pino writes only to stdout. Transports and multistream send logs elsewhere.';
const pinoTransports = [
  { selector: "CallExpression[callee.name='pino'] Property[key.name='transport']", message: pinoOnlyToStdout },
  {
    selector: "MemberExpression[object.name='pino'][property.name=/^(?:transport|multistream)$/]",
    message: pinoOnlyToStdout,
  },
];

/**
 * ADR-013, SEC-DATA-03: the boundary check sees only modules loaded by name. A
 * module loaded by a computed name, or through createRequire, could be a
 * telemetry SDK it never sees.
 */
const namedLoadsOnly = 'ADR-013: load modules by a fixed name, so the boundary check can see them.';
const computedLoads = [{ selector: "ImportExpression[source.type!='Literal']", message: namedLoadsOnly }];

const productSyntax = [
  ...rawHtmlInjection,
  ...tlsChecksOff,
  ...reasonCodeAssertions,
  ...networkDestructuring,
  ...environmentThroughGlobal,
  ...outputBypasses,
  ...pinoTransports,
  ...computedLoads,
];

/** Randomness must be unpredictable. */
const mathRandom = { object: 'Math', property: 'random', message: 'Math.random is predictable. Use node:crypto.' };

/**
 * Import bans for product code. Only config may import node:process (for the
 * environment); everything else uses the global `process` for signals and exit.
 */
const processModule = ['node:process', 'process'].map((name) => ({ name, message: configOnly }));
const productImportBans = [
  ...processModule,
  ...['node:console', 'console'].map((name) => ({ name, message: loggerOnly })),
  // pino publishes each line on a diagnostics channel before its hooks run, and
  // web frameworks publish requests the same way; nothing of ours listens.
  ...['node:diagnostics_channel', 'diagnostics_channel'].map((name) => ({
    name,
    message: 'ADR-013: diagnostics channels carry data before the logger redacts it.',
  })),
  ...['node:module', 'module'].map((name) => ({ name, importNames: ['createRequire'], message: namedLoadsOnly })),
];

/** The property bans of all product code. Flat config replaces a rule's options per block, so blocks that add to it repeat these. */
const productProperties = [mathRandom, { object: 'process', property: 'env', message: configOnly }, ...outputStreams];

/**
 * SEC-WEB-06, SEC-DATA-04: how the API checks input, writes answers and
 * answers errors and unknown addresses is set once, in server.ts and
 * contract.ts. Set anywhere else, a plugin could answer in a shape of its own
 * or outside the zod schemas; and a not-found handler or a reply serializer
 * isn't a route, so the contract's check at start can't see it.
 */
const apiContractOnly =
  'SEC-WEB-06, SEC-DATA-04: set once, in apps/api/src/server.ts or contract.ts, so every route answers through the contract.';
const apiSetters = [
  'setErrorHandler',
  'setNotFoundHandler',
  'setValidatorCompiler',
  'setSerializerCompiler',
  'setReplySerializer',
  // A reply's own serializer writes an answer whole, past its route's schema.
  'serializer',
  // A body parser of its own may read past a route's bodyLimit (a stream-style parser does).
  'addContentTypeParser',
  'removeContentTypeParser',
  'removeAllContentTypeParsers',
].map((property) => ({ property, message: apiContractOnly }));

/**
 * SEC-WEB-06: an onSend hook runs after an answer is written, and could send
 * what no schema declares in its place. The contract refuses one on a route;
 * this refuses one on a plugin, which its check at start can't see.
 */
const apiSendHooks = [
  {
    selector: "CallExpression[callee.property.name='addHook'][arguments.0.value='onSend']",
    message: 'SEC-WEB-06: an onSend hook could rewrite an answer after it was written; only contract.ts adds one.',
  },
];

/** Node's network globals. XMLHttpRequest and EventSource aren't Node globals, so they aren't listed. */
const networkGlobals = ['fetch', 'WebSocket'].map((name) => ({ name, message: outboundOnly }));

export default defineConfig([
  globalIgnores([
    '**/node_modules/',
    '**/dist/',
    '**/coverage/',
    'Documents/',
    '.playwright-mcp/',
    // Review agents' own copies of the repository.
    '.claude/',
    'tooling/gate-proofs/fixtures/',
  ]),

  {
    linterOptions: {
      reportUnusedDisableDirectives: 'error',
      reportUnusedInlineConfigs: 'error',
    },
  },

  eslint.configs.recommended,
  comments.recommended,
  {
    rules: {
      // Rule Book §5: every eslint-disable carries a written reason.
      '@eslint-community/eslint-comments/require-description': ['error', { ignore: ['eslint-enable'] }],
      eqeqeq: ['error', 'always'],
      'no-new-func': 'error',
    },
  },

  {
    files: ['**/*.{ts,tsx}'],
    extends: [tseslint.configs.strictTypeChecked, tseslint.configs.stylisticTypeChecked],
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      '@typescript-eslint/restrict-template-expressions': ['error', { allowNumber: true }],
      '@typescript-eslint/switch-exhaustiveness-check': 'error',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
    },
  },

  {
    files: ['**/*.js', '**/*.mjs', '**/*.cjs'],
    extends: [tseslint.configs.disableTypeChecked],
    languageOptions: { globals: globals.node },
  },

  // Product code: packages and apps.
  {
    files: ['packages/**/*.{ts,tsx}', 'apps/**/*.{ts,tsx}'],
    plugins: {
      agentx: {
        rules: {
          'authority-tables-through-signed-state': authorityTablesThroughSignedState,
          'no-string-built-sql': noStringBuiltSql,
          'signed-state-steps-in-audit-module': signedStateStepsInAuditModule,
          'tenant-setting-only-in-with-tenant': tenantSettingOnlyInWithTenant,
        },
      },
    },
    rules: {
      'no-console': 'error',
      'agentx/authority-tables-through-signed-state': ['error', { tables: authorityTables }],
      'agentx/no-string-built-sql': 'error',
      'agentx/signed-state-steps-in-audit-module': 'error',
      'agentx/tenant-setting-only-in-with-tenant': 'error',
      'no-restricted-syntax': ['error', ...productSyntax],
      'no-restricted-properties': ['error', ...productProperties],
      'no-restricted-imports': ['error', { paths: productImportBans }],
    },
  },

  // The API's contract: only its own two files set how every route checks, answers and fails.
  {
    files: ['apps/api/**/*.{ts,tsx}'],
    ignores: ['apps/api/src/server.ts', 'apps/api/src/contract.ts'],
    rules: {
      'no-restricted-properties': ['error', ...productProperties, ...apiSetters],
      'no-restricted-syntax': ['error', ...productSyntax, ...apiSendHooks],
    },
  },

  // ADR-005 §4: withTenant's own file sets the tenant. Tests read the setting to
  // prove it is cleared, and the test harness builds tenant tables with the
  // policy that names it; neither ships.
  {
    files: ['packages/platform/src/db/tenant.ts', '**/*.test.{ts,tsx}', 'packages/testing/**/*.{ts,tsx}'],
    rules: { 'agentx/tenant-setting-only-in-with-tenant': 'off' },
  },

  // ADR-012 §2, A3c: the signed-row steps are written in @agentx/platform/db
  // and used by the audit module's signed states, which sign every change they
  // make. **These four entries are the whole set of places allowed to hold
  // them**: another one is a change to the wall itself, not a convenience, and
  // each of the two that ship has a gate proof (lint-authority.test.ts). Tests
  // and the harness may call them to prove what they do; neither ships.
  {
    files: [
      'packages/platform/src/db/**/*.{ts,tsx}',
      'packages/core/src/modules/audit/**/*.{ts,tsx}',
      '**/*.test.{ts,tsx}',
      'packages/testing/**/*.{ts,tsx}',
    ],
    rules: { 'agentx/signed-state-steps-in-audit-module': 'off' },
  },

  // An authority table's own name and subject type are written where the table
  // is declared, which the rule sees for itself. Tests and the harness build
  // tables of their own with names of their own (the A3c fixtures), so the
  // rule would read their fixtures as product code.
  {
    files: ['**/*.test.{ts,tsx}', 'packages/testing/**/*.{ts,tsx}'],
    rules: { 'agentx/authority-tables-through-signed-state': 'off' },
  },

  // The config module is the one place that reads the environment. Flat config
  // replaces a rule's options per block, so the other entries are repeated.
  {
    files: ['packages/platform/src/config/**/*.{ts,tsx}'],
    rules: {
      'no-restricted-properties': ['error', mathRandom, ...outputStreams],
      'no-restricted-imports': [
        'error',
        {
          paths: [
            ...productImportBans.filter((ban) => !processModule.includes(ban)),
            // It may import node:process for the environment, but not the output streams.
            ...['node:process', 'process'].map((name) => ({
              name,
              importNames: ['stdout', 'stderr'],
              message: loggerOnly,
            })),
          ],
        },
      ],
    },
  },

  // Server code reaches the network only through the allowlisted client. The
  // console is browser code that calls its own origin, so it is left out.
  // Node's `global` is declared here, or the rule can't see `global.fetch` in
  // TypeScript files (the type-aware parser only knows the standard globals).
  {
    files: ['packages/**/*.{ts,tsx}', 'apps/**/*.{ts,tsx}'],
    ignores: ['apps/console/**', 'packages/platform/src/outbound/**'],
    languageOptions: { globals: { global: 'readonly' } },
    rules: {
      'no-restricted-globals': [
        'error',
        { globals: networkGlobals, checkGlobalObject: true, globalObjects: ['global'] },
      ],
    },
  },

  // Business code in core also takes its time from the Clock (ADR-006 §3).
  {
    files: ['packages/core/**/*.{ts,tsx}'],
    ignores: ['packages/core/src/shared-kernel/clock.ts'],
    rules: {
      'no-restricted-syntax': ['error', ...productSyntax, ...wallClock],
    },
  },
]);
