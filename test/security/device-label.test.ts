/**
 * Unit tests for buildDeviceLabel and buildDeviceFingerprint
 * (src/security/deviceLabel.ts)
 *
 * Pure unit tests — no network, no D1, no Worker required.
 * Runs under node:test via tsx.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { buildDeviceLabel, buildDeviceFingerprint } from '../../src/security/deviceLabel.js';

// ─── buildDeviceLabel ────────────────────────────────────────

describe('buildDeviceLabel', () => {
  it('returns "Unknown browser" for null UA', () => {
    assert.equal(buildDeviceLabel(null), 'Unknown browser');
  });

  it('returns "Unknown browser" for empty UA', () => {
    assert.equal(buildDeviceLabel(''), 'Unknown browser');
  });

  it('returns "Unknown browser" for garbage UA', () => {
    assert.equal(buildDeviceLabel('not-a-browser/1.0'), 'Unknown browser on Unknown OS');
  });

  it('detects Chrome on macOS', () => {
    const ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
    assert.equal(buildDeviceLabel(ua), 'Chrome 120 on macOS');
  });

  it('detects Firefox on Windows', () => {
    const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0';
    assert.equal(buildDeviceLabel(ua), 'Firefox 128 on Windows');
  });

  it('detects Safari on iOS', () => {
    const ua = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1';
    assert.equal(buildDeviceLabel(ua), 'Safari 17 on iOS');
  });

  it('detects Edge on Windows (Chromium-based)', () => {
    const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0';
    assert.equal(buildDeviceLabel(ua), 'Edge 120 on Windows');
  });

  it('detects Chrome on Android', () => {
    const ua = 'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36';
    assert.equal(buildDeviceLabel(ua), 'Chrome 119 on Android');
  });

  it('detects Firefox on Linux', () => {
    const ua = 'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0';
    assert.equal(buildDeviceLabel(ua), 'Firefox 128 on Linux');
  });
});

// ─── buildDeviceFingerprint ──────────────────────────────────

describe('buildDeviceFingerprint', () => {
  it('returns a 64-char hex string (SHA-256)', async () => {
    const fp = await buildDeviceFingerprint('Mozilla/5.0', 'US');
    assert.equal(fp.length, 64);
    assert.match(fp, /^[0-9a-f]{64}$/);
  });

  it('is stable across two calls with same inputs', async () => {
    const ua = 'Mozilla/5.0 (Test)';
    const country = 'CA';
    const fp1 = await buildDeviceFingerprint(ua, country);
    const fp2 = await buildDeviceFingerprint(ua, country);
    assert.equal(fp1, fp2);
  });

  it('differs when UA changes', async () => {
    const fp1 = await buildDeviceFingerprint('Mozilla/5.0 (UA-A)', 'US');
    const fp2 = await buildDeviceFingerprint('Mozilla/5.0 (UA-B)', 'US');
    assert.notEqual(fp1, fp2);
  });

  it('differs when country changes', async () => {
    const ua = 'Mozilla/5.0 (same-UA)';
    const fp1 = await buildDeviceFingerprint(ua, 'US');
    const fp2 = await buildDeviceFingerprint(ua, 'GB');
    assert.notEqual(fp1, fp2);
  });

  it('handles null UA gracefully', async () => {
    const fp = await buildDeviceFingerprint(null, 'US');
    assert.equal(fp.length, 64);
  });

  it('handles null country gracefully', async () => {
    const fp = await buildDeviceFingerprint('Mozilla/5.0', null);
    assert.equal(fp.length, 64);
  });

  it('handles both null inputs gracefully', async () => {
    const fp = await buildDeviceFingerprint(null, null);
    assert.equal(fp.length, 64);
  });
});
