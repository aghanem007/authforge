import { randomBytes, createHash } from 'crypto';
import { v4 as uuidv4 } from 'uuid';

export function generateSecureToken(length: number = 32): string {
  return randomBytes(length).toString('hex');
}

export function generateUuid(): string {
  return uuidv4();
}

export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

export function generateBackupCodes(count: number = 10): string[] {
  const codes: string[] = [];
  for (let i = 0; i < count; i++) {
    // Format: XXXX-XXXX-XXXX (12 chars + 2 dashes)
    const code = randomBytes(6).toString('hex').toUpperCase();
    const formatted = `${code.slice(0, 4)}-${code.slice(4, 8)}-${code.slice(8, 12)}`;
    codes.push(formatted);
  }
  return codes;
}

export function generateApiKey(): { key: string; prefix: string; hash: string } {
  // Format: af_XXXXXXXX_YYYYYYYYYYYYYYYYYYYYYYYY
  const prefix = 'af';
  const identifier = randomBytes(4).toString('hex');
  const secret = randomBytes(16).toString('hex');
  const key = `${prefix}_${identifier}_${secret}`;
  const hash = hashToken(key);

  return {
    key,
    prefix: `${prefix}_${identifier}`,
    hash,
  };
}

export function constantTimeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

export function generateDeviceFingerprint(userAgent: string, ip: string): string {
  const data = `${userAgent}:${ip}`;
  return createHash('sha256').update(data).digest('hex').slice(0, 16);
}
