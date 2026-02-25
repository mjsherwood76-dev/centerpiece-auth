/**
 * Email Module Unit Tests — centerpiece-auth
 *
 * Tests for:
 * - sendgridClient.ts — SendGrid HTTP client (fetch mock)
 * - templates.ts — HTML email template builders, escaping, color validation
 * - send.ts — High-level send functions, graceful degradation, structured logging
 */
import { describe, it, beforeEach, afterEach, mock } from 'node:test';
import assert from 'node:assert/strict';

import { sendViaSendGrid, type SendGridMessage } from '../src/email/sendgridClient.js';
import {
  escapeHtml,
  validateCssColor,
  extractColorsFromBranding,
  buildPasswordResetEmail,
  buildWelcomeEmail,
  buildPasswordChangedEmail,
} from '../src/email/templates.js';
import {
  sendPasswordResetEmail,
  sendWelcomeEmail,
  sendPasswordChangedEmail,
} from '../src/email/send.js';
import type { TenantBranding } from '../src/branding.js';

// ─── Save originals for safe restoration ────────────────────

const _originalFetch = globalThis.fetch;
const _originalConsoleLog = console.log;

// ─── Fixtures ───────────────────────────────────────────────

const mockBranding: TenantBranding = {
  tenantId: 'test-tenant',
  storeName: 'Test Store',
  logoUrl: null,
  cssVariables: ':root { --primary: 221 83% 53%; --background: 0 0% 100%; }',
  googleFontsLinks: '',
};

function mockEnv(overrides: Record<string, unknown> = {}) {
  return {
    SENDGRID_API_KEY: 'SG.test-key',
    EMAIL_FROM: 'noreply@centerpiecelab.com',
    EMAIL_FROM_NAME: 'Centerpiece Lab',
    ...overrides,
  } as any;
}

const testMessage: SendGridMessage = {
  to: { email: 'user@example.com', name: 'User' },
  from: { email: 'noreply@test.com', name: 'Test' },
  subject: 'Test Subject',
  html: '<p>Test</p>',
  text: 'Test',
};

// ─── sendgridClient.ts ─────────────────────────────────────

describe('sendViaSendGrid', () => {
  afterEach(() => {
    globalThis.fetch = _originalFetch;
    console.log = _originalConsoleLog;
    mock.restoreAll();
  });

  it('should return success on 202 Accepted', async () => {
    mock.method(globalThis, 'fetch', async () => new Response(null, { status: 202 }));

    const result = await sendViaSendGrid('test-key', testMessage);

    assert.equal(result.success, true);
    assert.equal(result.statusCode, 202);
    assert.equal(result.failureClass, undefined);
  });

  it('should return permanent failure on 400 Bad Request', async () => {
    mock.method(globalThis, 'fetch', async () =>
      new Response('{"errors":[{"message":"Bad Request"}]}', { status: 400 })
    );

    const result = await sendViaSendGrid('test-key', testMessage);

    assert.equal(result.success, false);
    assert.equal(result.statusCode, 400);
    assert.equal(result.failureClass, 'permanent');
    assert.ok(result.error?.includes('Bad Request'));
  });

  it('should return transient failure on 429 and retry', async () => {
    let callCount = 0;
    mock.method(globalThis, 'fetch', async () => {
      callCount++;
      return new Response('Rate limited', { status: 429 });
    });

    const result = await sendViaSendGrid('test-key', testMessage);

    assert.equal(result.success, false);
    assert.equal(result.statusCode, 429);
    assert.equal(result.failureClass, 'transient');
    // Should have retried once (2 total calls)
    assert.equal(callCount, 2);
  });

  it('should return transient failure on 500 and retry', async () => {
    let callCount = 0;
    mock.method(globalThis, 'fetch', async () => {
      callCount++;
      return new Response('Server Error', { status: 500 });
    });

    const result = await sendViaSendGrid('test-key', testMessage);

    assert.equal(result.success, false);
    assert.equal(result.statusCode, 500);
    assert.equal(result.failureClass, 'transient');
    assert.equal(callCount, 2);
  });

  it('should succeed on retry if first attempt fails transiently', async () => {
    let callCount = 0;
    mock.method(globalThis, 'fetch', async () => {
      callCount++;
      if (callCount === 1) return new Response('Server Error', { status: 500 });
      return new Response(null, { status: 202 });
    });

    const result = await sendViaSendGrid('test-key', testMessage);

    assert.equal(result.success, true);
    assert.equal(result.statusCode, 202);
    assert.equal(callCount, 2);
  });

  it('should handle network errors without throwing', async () => {
    mock.method(globalThis, 'fetch', async () => {
      throw new Error('Network timeout');
    });

    // Should NOT throw — returns failure result
    const result = await sendViaSendGrid('test-key', testMessage);

    assert.equal(result.success, false);
    assert.equal(result.statusCode, 0);
    assert.equal(result.failureClass, 'transient');
    assert.ok(result.error?.includes('Network timeout'));
  });

  it('should send correct request body matching SendGrid v3 schema', async () => {
    let capturedBody: Record<string, unknown> | undefined;
    mock.method(globalThis, 'fetch', async (_url: string | URL | Request, init?: RequestInit) => {
      if (init?.body) capturedBody = JSON.parse(init.body as string);
      return new Response(null, { status: 202 });
    });

    await sendViaSendGrid('test-key', {
      to: { email: 'user@example.com', name: 'User' },
      from: { email: 'noreply@test.com', name: 'Sender' },
      replyTo: { email: 'reply@test.com' },
      subject: 'Test Subject',
      html: '<p>Hello</p>',
      text: 'Hello',
    });

    assert.ok(capturedBody, 'Request body should be captured');
    assert.ok(Array.isArray(capturedBody.personalizations), 'personalizations is an array');
    const personalizations = capturedBody.personalizations as any[];
    assert.equal(personalizations.length, 1);
    assert.deepStrictEqual(personalizations[0].to, [{ email: 'user@example.com', name: 'User' }]);
    assert.deepStrictEqual(capturedBody.from, { email: 'noreply@test.com', name: 'Sender' });
    assert.equal(capturedBody.subject, 'Test Subject');
    assert.deepStrictEqual(capturedBody.reply_to, { email: 'reply@test.com' });

    const content = capturedBody.content as any[];
    assert.ok(content.some((c: any) => c.type === 'text/html' && c.value === '<p>Hello</p>'));
    assert.ok(content.some((c: any) => c.type === 'text/plain' && c.value === 'Hello'));
  });

  it('should include Authorization header with Bearer token', async () => {
    let capturedHeaders: Record<string, string> | undefined;
    mock.method(globalThis, 'fetch', async (_url: string | URL | Request, init?: RequestInit) => {
      capturedHeaders = Object.fromEntries(
        Object.entries(init?.headers || {})
      );
      return new Response(null, { status: 202 });
    });

    await sendViaSendGrid('SG.my-secret-key', testMessage);

    assert.ok(capturedHeaders);
    assert.equal(capturedHeaders['Authorization'], 'Bearer SG.my-secret-key');
    assert.equal(capturedHeaders['Content-Type'], 'application/json');
  });
});

// ─── templates.ts ───────────────────────────────────────────

describe('escapeHtml', () => {
  it('should escape all HTML special characters', () => {
    const input = '<script>alert("xss")&</script>';
    const result = escapeHtml(input);
    assert.ok(!result.includes('<script>'), 'Should not contain raw <script> tag');
    assert.ok(result.includes('&lt;script&gt;'));
    assert.ok(result.includes('&quot;'));
    assert.ok(result.includes('&amp;'));
  });

  it('should escape single quotes', () => {
    assert.ok(escapeHtml("it's").includes('&#39;'));
  });

  it('should pass through safe strings unchanged', () => {
    assert.equal(escapeHtml('Hello World'), 'Hello World');
  });
});

describe('validateCssColor', () => {
  it('should accept valid hex colors', () => {
    assert.equal(validateCssColor('#fff'), '#fff');
    assert.equal(validateCssColor('#2563eb'), '#2563eb');
    assert.equal(validateCssColor('#2563ebff'), '#2563ebff');
  });

  it('should accept rgb colors', () => {
    assert.ok(validateCssColor('rgb(37,99,235)') !== null);
  });

  it('should accept hsl colors', () => {
    assert.ok(validateCssColor('hsl(217,91%,53%)') !== null);
  });

  it('should reject invalid strings', () => {
    assert.equal(validateCssColor('not-a-color'), null);
    assert.equal(validateCssColor(''), null);
    assert.equal(validateCssColor('url(javascript:alert(1))'), null);
    assert.equal(validateCssColor('red'), null); // Named colors rejected
  });

  it('should reject null/undefined inputs', () => {
    assert.equal(validateCssColor(null as any), null);
    assert.equal(validateCssColor(undefined as any), null);
  });
});

describe('extractColorsFromBranding', () => {
  it('should extract HSL channel values and convert to hsl() format', () => {
    const branding: TenantBranding = {
      tenantId: 'test',
      storeName: 'Test',
      logoUrl: null,
      cssVariables: ':root { --primary: 221 83% 53%; --background: 0 0% 100%; }',
      googleFontsLinks: '',
    };
    const colors = extractColorsFromBranding(branding);
    assert.ok(colors.primaryColor.includes('hsl'), `Primary should be hsl, got: ${colors.primaryColor}`);
    assert.ok(colors.backgroundColor.includes('hsl'), `Background should be hsl, got: ${colors.backgroundColor}`);
  });

  it('should return default colors when cssVariables is empty', () => {
    const branding: TenantBranding = {
      tenantId: 'test',
      storeName: 'Test',
      logoUrl: null,
      cssVariables: '',
      googleFontsLinks: '',
    };
    const colors = extractColorsFromBranding(branding);
    assert.equal(colors.primaryColor, '#2563eb');
    assert.equal(colors.backgroundColor, '#ffffff');
  });

  it('should return defaults when cssVariables has no matching variables', () => {
    const branding: TenantBranding = {
      tenantId: 'test',
      storeName: 'Test',
      logoUrl: null,
      cssVariables: ':root { --unrelated: red; }',
      googleFontsLinks: '',
    };
    const colors = extractColorsFromBranding(branding);
    assert.equal(colors.primaryColor, '#2563eb');
    assert.equal(colors.backgroundColor, '#ffffff');
  });
});

describe('buildPasswordResetEmail', () => {
  it('should contain the reset URL', () => {
    const result = buildPasswordResetEmail({
      branding: { storeName: 'My Store', logoUrl: null, primaryColor: '#2563eb', backgroundColor: '#fff' },
      resetUrl: 'https://auth.test/reset?token=abc123',
      expiresInMinutes: 60,
    });
    assert.ok(result.html.includes('https://auth.test/reset?token=abc123'));
    assert.ok(result.text.includes('https://auth.test/reset?token=abc123'));
  });

  it('should contain the store name', () => {
    const result = buildPasswordResetEmail({
      branding: { storeName: 'My Store', logoUrl: null, primaryColor: '#2563eb', backgroundColor: '#fff' },
      resetUrl: 'https://auth.test/reset?token=abc123',
      expiresInMinutes: 60,
    });
    assert.ok(result.html.includes('My Store'));
    assert.ok(result.text.includes('My Store'));
  });

  it('should contain expiry time', () => {
    const result = buildPasswordResetEmail({
      branding: { storeName: 'My Store', logoUrl: null, primaryColor: '#2563eb', backgroundColor: '#fff' },
      resetUrl: 'https://auth.test/reset?token=abc123',
      expiresInMinutes: 30,
    });
    assert.ok(result.html.includes('30 minutes'));
    assert.ok(result.text.includes('30 minutes'));
  });

  it('should contain Powered by Centerpiece Lab footer', () => {
    const result = buildPasswordResetEmail({
      branding: { storeName: 'My Store', logoUrl: null, primaryColor: '#2563eb', backgroundColor: '#fff' },
      resetUrl: 'https://test.com/reset',
      expiresInMinutes: 60,
    });
    assert.ok(result.html.includes('Powered by Centerpiece Lab'));
  });

  it('should generate a subject line with store name', () => {
    const result = buildPasswordResetEmail({
      branding: { storeName: 'My Store', logoUrl: null, primaryColor: '#2563eb', backgroundColor: '#fff' },
      resetUrl: 'https://test.com/reset',
      expiresInMinutes: 60,
    });
    assert.ok(result.subject.includes('My Store'));
  });
});

describe('buildWelcomeEmail', () => {
  it('should contain the user name and store name', () => {
    const result = buildWelcomeEmail({
      branding: { storeName: 'My Store', logoUrl: null, primaryColor: '#2563eb', backgroundColor: '#fff' },
      userName: 'Alice',
      loginUrl: 'https://auth.test/login',
    });
    assert.ok(result.html.includes('Alice'), 'HTML should contain user name');
    assert.ok(result.html.includes('My Store'), 'HTML should contain store name');
    assert.ok(result.text.includes('Alice'), 'Text should contain user name');
  });

  it('should contain the login URL', () => {
    const result = buildWelcomeEmail({
      branding: { storeName: 'My Store', logoUrl: null, primaryColor: '#2563eb', backgroundColor: '#fff' },
      userName: 'Alice',
      loginUrl: 'https://auth.test/login?tenant=test',
    });
    assert.ok(result.html.includes('https://auth.test/login?tenant=test'));
    assert.ok(result.text.includes('https://auth.test/login?tenant=test'));
  });

  it('should contain Powered by Centerpiece Lab footer', () => {
    const result = buildWelcomeEmail({
      branding: { storeName: 'My Store', logoUrl: null, primaryColor: '#2563eb', backgroundColor: '#fff' },
      userName: 'Alice',
      loginUrl: 'https://test.com/login',
    });
    assert.ok(result.html.includes('Powered by Centerpiece Lab'));
  });

  it('should NOT render HTML when user name contains HTML tags', () => {
    const result = buildWelcomeEmail({
      branding: { storeName: 'My Store', logoUrl: null, primaryColor: '#2563eb', backgroundColor: '#fff' },
      userName: '<b>Bold</b>',
      loginUrl: 'https://test.com/login',
    });
    // The <b> tag should be escaped, not rendered as bold
    assert.ok(!result.html.includes('<b>Bold</b>'), 'Raw <b> tag should not appear in HTML');
    assert.ok(result.html.includes('&lt;b&gt;Bold&lt;/b&gt;'), 'HTML entities should be used');
  });
});

describe('buildPasswordChangedEmail', () => {
  it('should contain the store name', () => {
    const result = buildPasswordChangedEmail({
      branding: { storeName: 'My Store', logoUrl: null, primaryColor: '#2563eb', backgroundColor: '#fff' },
      userEmail: 'user@example.com',
      changedAt: new Date().toISOString(),
      forgotPasswordUrl: 'https://auth.test/forgot-password',
    });
    assert.ok(result.html.includes('My Store'));
  });

  it('should contain a timestamp', () => {
    const isoDate = '2026-02-25T12:00:00.000Z';
    const result = buildPasswordChangedEmail({
      branding: { storeName: 'My Store', logoUrl: null, primaryColor: '#2563eb', backgroundColor: '#fff' },
      userEmail: 'user@example.com',
      changedAt: isoDate,
      forgotPasswordUrl: 'https://auth.test/forgot-password',
    });
    // The HTML should contain the formatted date
    assert.ok(result.html.includes('2026'), 'HTML should contain year from timestamp');
    assert.ok(result.text.includes('2026'), 'Text should contain year from timestamp');
  });

  it('should contain "if this wasn\'t you" security copy', () => {
    const result = buildPasswordChangedEmail({
      branding: { storeName: 'My Store', logoUrl: null, primaryColor: '#2563eb', backgroundColor: '#fff' },
      userEmail: 'user@example.com',
      changedAt: new Date().toISOString(),
      forgotPasswordUrl: 'https://auth.test/forgot-password',
    });
    assert.ok(result.html.includes('did not make this change'));
    assert.ok(result.text.includes('did not make this change'));
  });

  it('should contain the forgot-password URL', () => {
    const result = buildPasswordChangedEmail({
      branding: { storeName: 'My Store', logoUrl: null, primaryColor: '#2563eb', backgroundColor: '#fff' },
      userEmail: 'user@example.com',
      changedAt: new Date().toISOString(),
      forgotPasswordUrl: 'https://auth.test/forgot-password?tenant=test',
    });
    assert.ok(result.html.includes('https://auth.test/forgot-password?tenant=test'));
    assert.ok(result.text.includes('https://auth.test/forgot-password?tenant=test'));
  });

  it('should contain Powered by Centerpiece Lab footer', () => {
    const result = buildPasswordChangedEmail({
      branding: { storeName: 'My Store', logoUrl: null, primaryColor: '#2563eb', backgroundColor: '#fff' },
      userEmail: 'user@example.com',
      changedAt: new Date().toISOString(),
      forgotPasswordUrl: 'https://auth.test/forgot-password',
    });
    assert.ok(result.html.includes('Powered by Centerpiece Lab'));
  });

  it('should escape store name with HTML characters', () => {
    const result = buildPasswordChangedEmail({
      branding: { storeName: '<script>evil</script> Store', logoUrl: null, primaryColor: '#2563eb', backgroundColor: '#fff' },
      userEmail: 'user@example.com',
      changedAt: new Date().toISOString(),
      forgotPasswordUrl: 'https://auth.test/forgot-password',
    });
    assert.ok(!result.html.includes('<script>evil</script>'), 'Raw script tag should not be in HTML');
    assert.ok(result.html.includes('&lt;script&gt;evil&lt;/script&gt;'), 'Script tag should be escaped');
  });
});

// ─── send.ts ────────────────────────────────────────────────

describe('sendPasswordResetEmail', () => {
  afterEach(() => {
    globalThis.fetch = _originalFetch;
    console.log = _originalConsoleLog;
    mock.restoreAll();
  });

  it('should skip when SENDGRID_API_KEY is not configured', async () => {
    let fetchCalled = false;
    mock.method(globalThis, 'fetch', async () => {
      fetchCalled = true;
      return new Response(null, { status: 202 });
    });

    const logs: string[] = [];
    mock.method(console, 'log', (msg: string) => logs.push(msg));

    await sendPasswordResetEmail(
      mockEnv({ SENDGRID_API_KEY: undefined }),
      'user@example.com',
      'https://auth.test/reset',
      mockBranding
    );

    assert.equal(fetchCalled, false, 'fetch should not be called');
    const logEntry = logs.find(l => l.includes('email.skipped'));
    assert.ok(logEntry, 'Should log email.skipped');
    const parsed = JSON.parse(logEntry!);
    assert.equal(parsed.type, 'password_reset');
    assert.equal(parsed.reason, 'SENDGRID_API_KEY not configured');
  });

  it('should call SendGrid and log success', async () => {
    mock.method(globalThis, 'fetch', async () => new Response(null, { status: 202 }));

    const logs: string[] = [];
    mock.method(console, 'log', (msg: string) => logs.push(msg));

    await sendPasswordResetEmail(
      mockEnv(),
      'user@example.com',
      'https://auth.test/reset?token=abc',
      mockBranding
    );

    const logEntry = logs.find(l => l.includes('email.sent'));
    assert.ok(logEntry, 'Should log email.sent');
    const parsed = JSON.parse(logEntry!);
    assert.equal(parsed.type, 'password_reset');
    assert.equal(parsed.statusCode, 202);
    // Email should be redacted
    assert.ok(parsed.to.startsWith('***@'), 'Email should be redacted');
  });

  it('should log failure but not throw when SendGrid returns error', async () => {
    mock.method(globalThis, 'fetch', async () =>
      new Response('Unauthorized', { status: 401 })
    );

    const logs: string[] = [];
    mock.method(console, 'log', (msg: string) => logs.push(msg));

    // Should NOT throw
    await sendPasswordResetEmail(
      mockEnv(),
      'user@example.com',
      'https://auth.test/reset?token=abc',
      mockBranding
    );

    const logEntry = logs.find(l => l.includes('email.failed'));
    assert.ok(logEntry, 'Should log email.failed');
    const parsed = JSON.parse(logEntry!);
    assert.equal(parsed.type, 'password_reset');
    assert.equal(parsed.failureClass, 'permanent');
  });
});

describe('sendWelcomeEmail', () => {
  afterEach(() => {
    globalThis.fetch = _originalFetch;
    console.log = _originalConsoleLog;
    mock.restoreAll();
  });

  it('should skip when SENDGRID_API_KEY is not configured', async () => {
    const logs: string[] = [];
    mock.method(console, 'log', (msg: string) => logs.push(msg));

    await sendWelcomeEmail(
      mockEnv({ SENDGRID_API_KEY: undefined }),
      'user@example.com',
      'Alice',
      'https://auth.test/login',
      mockBranding
    );

    const logEntry = logs.find(l => l.includes('email.skipped'));
    assert.ok(logEntry, 'Should log email.skipped');
    const parsed = JSON.parse(logEntry!);
    assert.equal(parsed.type, 'welcome');
  });

  it('should send welcome email and log success', async () => {
    mock.method(globalThis, 'fetch', async () => new Response(null, { status: 202 }));

    const logs: string[] = [];
    mock.method(console, 'log', (msg: string) => logs.push(msg));

    await sendWelcomeEmail(
      mockEnv(),
      'user@example.com',
      'Alice',
      'https://auth.test/login',
      mockBranding
    );

    const logEntry = logs.find(l => l.includes('email.sent'));
    assert.ok(logEntry, 'Should log email.sent');
    const parsed = JSON.parse(logEntry!);
    assert.equal(parsed.type, 'welcome');
  });
});

describe('sendPasswordChangedEmail', () => {
  afterEach(() => {
    globalThis.fetch = _originalFetch;
    console.log = _originalConsoleLog;
    mock.restoreAll();
  });

  it('should skip when SENDGRID_API_KEY is not configured', async () => {
    const logs: string[] = [];
    mock.method(console, 'log', (msg: string) => logs.push(msg));

    await sendPasswordChangedEmail(
      mockEnv({ SENDGRID_API_KEY: undefined }),
      'user@example.com',
      mockBranding,
      'https://auth.test/forgot-password'
    );

    const logEntry = logs.find(l => l.includes('email.skipped'));
    assert.ok(logEntry, 'Should log email.skipped');
    const parsed = JSON.parse(logEntry!);
    assert.equal(parsed.type, 'password_changed');
  });

  it('should send password-changed email and log success', async () => {
    mock.method(globalThis, 'fetch', async () => new Response(null, { status: 202 }));

    const logs: string[] = [];
    mock.method(console, 'log', (msg: string) => logs.push(msg));

    await sendPasswordChangedEmail(
      mockEnv(),
      'user@example.com',
      mockBranding,
      'https://auth.test/forgot-password'
    );

    const logEntry = logs.find(l => l.includes('email.sent'));
    assert.ok(logEntry, 'Should log email.sent');
    const parsed = JSON.parse(logEntry!);
    assert.equal(parsed.type, 'password_changed');
  });

  it('should include correlation context in logs', async () => {
    mock.method(globalThis, 'fetch', async () => new Response(null, { status: 202 }));

    const logs: string[] = [];
    mock.method(console, 'log', (msg: string) => logs.push(msg));

    await sendPasswordChangedEmail(
      mockEnv(),
      'user@example.com',
      mockBranding,
      'https://auth.test/forgot-password',
      { tenantId: 'tenant-abc', userId: 'user-123' }
    );

    const logEntry = logs.find(l => l.includes('email.sent'));
    assert.ok(logEntry);
    const parsed = JSON.parse(logEntry!);
    assert.equal(parsed.tenantId, 'tenant-abc');
    assert.equal(parsed.userId, 'user-123');
  });
});
