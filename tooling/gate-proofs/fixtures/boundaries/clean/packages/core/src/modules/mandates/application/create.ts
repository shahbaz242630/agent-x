import { agent } from '../../agents/index.ts';
import { systemClock } from '../../../shared-kernel/clock.ts';
import { limit } from '../domain/limits.ts';
export const create = [agent, limit, systemClock];
