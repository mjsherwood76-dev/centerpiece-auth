/**
 * Request Tracing — Lightweight per-request observability for the Auth Worker.
 *
 * Lighter version of site-runtime's RequestTrace — omits logCplCall()
 * and logCacheOutcome() (auth worker doesn't call CPL or use cache).
 *
 * Provides:
 * - Per-request trace ID (correlationId) in `x-trace-id` response header
 * - Timer spans for Server-Timing header in browser DevTools
 */

export class RequestTrace {
  readonly traceId: string;
  private readonly timings: { name: string; durationMs: number; desc?: string }[] = [];
  private readonly requestStart: number;

  constructor(correlationId?: string) {
    this.traceId = correlationId || RequestTrace.generateShortId();
    this.requestStart = Date.now();
  }

  /**
   * Start a timing span. Returns a function to call when the span ends.
   */
  startTimer(name: string, description?: string): () => void {
    const start = Date.now();
    return () => {
      this.timings.push({ name, durationMs: Date.now() - start, desc: description });
    };
  }

  /**
   * Build the Server-Timing header value.
   */
  buildServerTimingHeader(): string {
    const totalMs = Date.now() - this.requestStart;
    const parts = this.timings.map(t => {
      let part = `${t.name};dur=${t.durationMs}`;
      if (t.desc) part += `;desc="${t.desc}"`;
      return part;
    });
    parts.push(`total;dur=${totalMs};desc="Total request"`);
    return parts.join(', ');
  }

  /**
   * Get response headers for this trace (x-trace-id + Server-Timing).
   */
  getResponseHeaders(): Record<string, string> {
    return {
      'x-trace-id': this.traceId,
      'Server-Timing': this.buildServerTimingHeader(),
    };
  }

  /**
   * Generate a short random ID for trace identification (fallback).
   */
  private static generateShortId(): string {
    const bytes = new Uint8Array(4);
    crypto.getRandomValues(bytes);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }
}
