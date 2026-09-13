import { Agent } from 'node:https';

export const agent = new Agent({ keepAlive: true });
