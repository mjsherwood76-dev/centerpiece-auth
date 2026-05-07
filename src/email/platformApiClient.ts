export interface TransactionalEmailInput {
  templateId: string;
  tenantId: string;
  recipient: { email: string; name?: string };
  locale?: string;
  variables: Record<string, unknown>;
  idempotencyKey?: string;
}

export interface TransactionalEmailResult {
  status: 'queued' | 'sent' | 'skipped';
  reason?: string;
  messageId?: string;
}

export interface PlatformApiEmailBinding {
  sendTransactionalEmail(input: TransactionalEmailInput): Promise<TransactionalEmailResult>;
}

export async function sendViaPlatformApi(
  binding: PlatformApiEmailBinding | undefined,
  input: TransactionalEmailInput,
): Promise<TransactionalEmailResult | null> {
  if (!binding) return null;
  return binding.sendTransactionalEmail(input);
}
