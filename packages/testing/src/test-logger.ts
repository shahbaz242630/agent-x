// The logger the tests build (S79: one copy where ~90 test files each wrote
// it out): the test service and release, info level, 1,000 events a minute,
// its lines to `destination`, a LogCapture to read back by default.
import { createLogger, type Logger, type LoggerOptions } from '@agentx/platform/observability';
import { LogCapture } from './log-scan.ts';

export function testLogger(destination: LoggerOptions['destination'] = new LogCapture()): Logger {
  return createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination,
  });
}
