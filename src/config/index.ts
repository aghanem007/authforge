import dotenv from 'dotenv';

dotenv.config();

export const config = {
  env: process.env['NODE_ENV'] ?? 'development',
  port: parseInt(process.env['PORT'] ?? '3000', 10),

  app: {
    baseUrl: process.env['APP_BASE_URL'] ?? 'http://localhost:3000',
  },

  database: {
    url: process.env['DATABASE_URL'] ?? 'postgresql://authforge:authforge@localhost:5432/authforge',
  },

  redis: {
    url: process.env['REDIS_URL'] ?? 'redis://localhost:6379',
  },

  jwt: {
    accessExpiry: process.env['JWT_ACCESS_EXPIRY'] ?? '15m',
    refreshExpiry: process.env['JWT_REFRESH_EXPIRY'] ?? '7d',
    issuer: process.env['JWT_ISSUER'] ?? 'authforge',
    privateKeyPath: process.env['JWT_PRIVATE_KEY_PATH'] ?? './keys/private.pem',
    publicKeyPath: process.env['JWT_PUBLIC_KEY_PATH'] ?? './keys/public.pem',
  },

  security: {
    maxLoginAttempts: parseInt(process.env['MAX_LOGIN_ATTEMPTS'] ?? '5', 10),
    lockoutDurationMinutes: parseInt(process.env['LOCKOUT_DURATION_MINUTES'] ?? '15', 10),
  },

  rateLimit: {
    max: parseInt(process.env['RATE_LIMIT_MAX'] ?? '100', 10),
    windowMs: parseInt(process.env['RATE_LIMIT_WINDOW_MS'] ?? '60000', 10),
  },

  mfa: {
    issuer: process.env['MFA_ISSUER'] ?? 'AuthForge',
    backupCodesCount: parseInt(process.env['MFA_BACKUP_CODES_COUNT'] ?? '10', 10),
  },

  email: {
    host: process.env['SMTP_HOST'],
    port: parseInt(process.env['SMTP_PORT'] ?? '587', 10),
    user: process.env['SMTP_USER'],
    pass: process.env['SMTP_PASS'],
    from: process.env['EMAIL_FROM'] ?? 'noreply@authforge.com',
  },
} as const;

export function validateConfig(): void {
  const required = [
    'DATABASE_URL',
    'REDIS_URL',
  ];

  const missing = required.filter(key => !process.env[key]);

  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }
}
