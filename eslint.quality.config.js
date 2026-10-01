// The garbage-code checks (partner, S69; memory `no-garbage-code`): the
// repository's own rules (eslint.config.js) plus SonarJS's recommended ones:
// needless complexity, duplicated branches and functions, dead stores,
// redundant code. `pnpm lint` (tooling/quality/lint.ts) runs this config once:
// the repository's own rules block as they always have, and a SonarJS rule
// is only reported until its findings are cleaned and it joins BLOCKING there.
import sonarjs from 'eslint-plugin-sonarjs';

import base from './eslint.config.js';

/**
 * SonarJS's recommended rules this repository doesn't take, each with why:
 * they measure no waste, and fire on what is right here.
 */
const NOT_TAKEN = {
  // Code-unit order is the point: canonical forms, sealed fields and sorted IDs must not change with a locale.
  'sonarjs/no-alphabetical-sort': 'off',
  // Answers are deliberate unions of outcomes (`found` | `refused` | …), typed by the compiler.
  'sonarjs/function-return-type': 'off',
  // Security heuristics, covered by CodeQL, gitleaks and review; they fire on test fixtures
  // (documentation addresses, localhost over http, temp directories) and on tooling that runs
  // git, docker and az by name on purpose.
  'sonarjs/no-hardcoded-ip': 'off',
  'sonarjs/no-clear-text-protocols': 'off',
  'sonarjs/publicly-writable-directories': 'off',
  'sonarjs/no-os-command-from-path': 'off',
  'sonarjs/hashing': 'off',
  // Duplicates @typescript-eslint/no-unused-vars, and flags the `_name` the repository leaves unused on purpose.
  'sonarjs/no-unused-vars': 'off',
  // Vitest already fails a file with no test; the gate proofs build theirs through a helper this rule can't see.
  'sonarjs/no-empty-test-file': 'off',
  // The log scrubber's and the secret checks' patterns are complex by necessity, each held by property tests.
  'sonarjs/regex-complexity': 'off',
  // A named alias documents what a plain type means (a SchemaProblem is a string that names no value).
  'sonarjs/redundant-type-aliases': 'off',
  // Slow and covered already (S70: together 44% of the run): @typescript-eslint/no-deprecated is on, SonarJS's
  // assertions-in-test-cases checks what assertions-in-tests does, and there is no AWS code here.
  'sonarjs/deprecation': 'off',
  'sonarjs/assertions-in-tests': 'off',
  'sonarjs/aws-restricted-ip-admin-access': 'off',
};

export default [...base, sonarjs.configs.recommended, { rules: NOT_TAKEN }];
