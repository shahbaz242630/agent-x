import type { Clock } from '../../../shared-kernel/clock.ts';
export const limit = (clock: Clock): Date => clock.now();
