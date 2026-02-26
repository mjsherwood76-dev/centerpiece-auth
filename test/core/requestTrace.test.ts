/**
 * Unit tests for RequestTrace.
 *
 * Verifies trace ID assignment and Server-Timing header generation.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { RequestTrace } from '../../src/core/requestTrace.js';

describe('RequestTrace', () => {
  it('traceId is the full correlationId when provided', () => {
    const trace = new RequestTrace('abc-123-full-uuid');
    assert.equal(trace.traceId, 'abc-123-full-uuid');
  });

  it('traceId is auto-generated when no correlationId provided', () => {
    const trace = new RequestTrace();
    assert.ok(trace.traceId, 'should have a traceId');
    assert.ok(trace.traceId.length > 0, 'traceId should be non-empty');
  });

  it('Server-Timing includes total;dur=X', () => {
    const trace = new RequestTrace('test-trace');
    const header = trace.buildServerTimingHeader();
    assert.ok(header.includes('total;dur='), 'should include total timing');
    assert.ok(header.includes('desc="Total request"'), 'should include total description');
  });

  it('getResponseHeaders() returns x-trace-id and Server-Timing', () => {
    const trace = new RequestTrace('header-test');
    const headers = trace.getResponseHeaders();
    assert.equal(headers['x-trace-id'], 'header-test');
    assert.ok(headers['Server-Timing'], 'should have Server-Timing');
    assert.ok(headers['Server-Timing'].includes('total;dur='), 'Server-Timing should include total');
  });
});
