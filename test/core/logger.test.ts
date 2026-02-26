/**
 * Unit tests for ConsoleJsonLogger.
 *
 * Verifies structured JSON output with required fields.
 */
import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { ConsoleJsonLogger } from '../../src/core/logger.js';

describe('ConsoleJsonLogger', () => {
  let captured: string[] = [];
  let origInfo: typeof console.info;
  let origError: typeof console.error;
  let origDebug: typeof console.debug;
  let origWarn: typeof console.warn;

  beforeEach(() => {
    captured = [];
    origInfo = console.info;
    origError = console.error;
    origDebug = console.debug;
    origWarn = console.warn;
    const capture = (line: string) => captured.push(line);
    console.info = capture as typeof console.info;
    console.error = capture as typeof console.error;
    console.debug = capture as typeof console.debug;
    console.warn = capture as typeof console.warn;
  });

  afterEach(() => {
    console.info = origInfo;
    console.error = origError;
    console.debug = origDebug;
    console.warn = origWarn;
  });

  it('info() produces JSON with level: "info", ts, correlationId, event', () => {
    const logger = new ConsoleJsonLogger();
    logger.info({ correlationId: 'test-123', event: 'test.event' });

    assert.equal(captured.length, 1);
    const parsed = JSON.parse(captured[0]!);
    assert.equal(parsed.level, 'info');
    assert.equal(parsed.correlationId, 'test-123');
    assert.equal(parsed.event, 'test.event');
    assert.ok(parsed.ts, 'should have ts field');
  });

  it('error() produces JSON with level: "error"', () => {
    const logger = new ConsoleJsonLogger();
    logger.error({ correlationId: 'err-456', event: 'test.error', message: 'boom' });

    assert.equal(captured.length, 1);
    const parsed = JSON.parse(captured[0]!);
    assert.equal(parsed.level, 'error');
    assert.equal(parsed.correlationId, 'err-456');
    assert.equal(parsed.event, 'test.error');
  });

  it('ad-hoc fields are included in JSON output', () => {
    const logger = new ConsoleJsonLogger();
    logger.info({
      correlationId: 'adhoc-789',
      event: 'test.adhoc',
      customField: 42,
      nested: { key: 'value' },
    });

    const parsed = JSON.parse(captured[0]!);
    assert.equal(parsed.customField, 42);
    assert.deepEqual(parsed.nested, { key: 'value' });
  });

  it('ts is a valid ISO 8601 timestamp', () => {
    const logger = new ConsoleJsonLogger();
    const before = new Date().toISOString();
    logger.info({ correlationId: 'ts-test', event: 'test.ts' });
    const after = new Date().toISOString();

    const parsed = JSON.parse(captured[0]!);
    assert.ok(parsed.ts >= before, 'ts should be >= before');
    assert.ok(parsed.ts <= after, 'ts should be <= after');
    // Verify it parses as a valid date
    const date = new Date(parsed.ts);
    assert.ok(!isNaN(date.getTime()), 'ts should parse as valid date');
  });
});
