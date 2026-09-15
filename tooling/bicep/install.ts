// `corepack pnpm tools`: installs the pinned Bicep compiler into .tools/ (once
// per clone, and in CI before the tests). The deploy/azure checks need it and
// never download it themselves: tests make no network calls (Rule Book §6).
import { ensureBicep } from './bicep.ts';

try {
  const installed = await ensureBicep();
  process.stdout.write(`bicep: ${installed}\n`);
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}
