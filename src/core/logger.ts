/**
 * Structured JSON Logger for the Auth Worker.
 *
 * Port of centerpiece-site-runtime's ConsoleJsonLogger.
 * Identical interface for future extraction into shared package.
 *
 * Every log line is a single JSON string with `level`, `ts`,
 * `correlationId`, `event`, plus ad-hoc fields.
 */

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export interface LogFields {
  correlationId: string;
  event: string;
  [key: string]: unknown;
}

export interface Logger {
  debug(fields: LogFields): void;
  info(fields: LogFields): void;
  warn(fields: LogFields): void;
  error(fields: LogFields): void;
}

export class ConsoleJsonLogger implements Logger {
  private write(level: LogLevel, fields: LogFields): void {
    const line = JSON.stringify({
      level,
      ts: new Date().toISOString(),
      ...fields,
    });

    switch (level) {
      case 'debug':
        console.debug(line);
        break;
      case 'info':
        console.info(line);
        break;
      case 'warn':
        console.warn(line);
        break;
      case 'error':
        console.error(line);
        break;
      default:
        console.log(line);
        break;
    }
  }

  debug(fields: LogFields): void {
    this.write('debug', fields);
  }
  info(fields: LogFields): void {
    this.write('info', fields);
  }
  warn(fields: LogFields): void {
    this.write('warn', fields);
  }
  error(fields: LogFields): void {
    this.write('error', fields);
  }
}
