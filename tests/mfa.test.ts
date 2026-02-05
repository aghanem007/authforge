import { describe, it, expect, beforeAll } from 'vitest';
import { buildApp } from '../src/app.js';
import { authenticator } from 'otplib';
import type { FastifyInstance } from 'fastify';

describe('MFA Routes', () => {
  let app: FastifyInstance;
  let accessToken: string;

  beforeAll(async () => {
    app = await buildApp();

    // Register a test user
    const registerResponse = await app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: {
        email: 'mfa@example.com',
        password: 'SecureP@ss123!',
      },
    });

    const { tokens } = JSON.parse(registerResponse.body).data;
    accessToken = tokens.accessToken;
  });

  describe('POST /mfa/setup', () => {
    it('should return QR code and secret', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/mfa/setup',
        headers: {
          authorization: `Bearer ${accessToken}`,
        },
      });

      expect(response.statusCode).toBe(200);

      const body = JSON.parse(response.body);
      expect(body.data.secret).toBeDefined();
      expect(body.data.qrCode).toContain('data:image/png;base64');
      expect(body.data.backupCodes).toHaveLength(10);
    });
  });

  describe('POST /mfa/verify', () => {
    it('should enable MFA with valid code', async () => {
      // Setup MFA first
      const setupResponse = await app.inject({
        method: 'POST',
        url: '/mfa/setup',
        headers: {
          authorization: `Bearer ${accessToken}`,
        },
      });

      const { secret } = JSON.parse(setupResponse.body).data;

      // Generate valid TOTP code
      const code = authenticator.generate(secret);

      // Verify and enable
      const response = await app.inject({
        method: 'POST',
        url: '/mfa/verify',
        headers: {
          authorization: `Bearer ${accessToken}`,
        },
        payload: {
          code,
        },
      });

      expect(response.statusCode).toBe(200);

      const body = JSON.parse(response.body);
      expect(body.success).toBe(true);
    });

    it('should reject invalid code', async () => {
      // Setup MFA
      await app.inject({
        method: 'POST',
        url: '/mfa/setup',
        headers: {
          authorization: `Bearer ${accessToken}`,
        },
      });

      // Try with invalid code
      const response = await app.inject({
        method: 'POST',
        url: '/mfa/verify',
        headers: {
          authorization: `Bearer ${accessToken}`,
        },
        payload: {
          code: '000000',
        },
      });

      expect(response.statusCode).toBe(400);
    });
  });

  describe('GET /mfa/backup-codes', () => {
    it('should return remaining backup codes count', async () => {
      const response = await app.inject({
        method: 'GET',
        url: '/mfa/backup-codes',
        headers: {
          authorization: `Bearer ${accessToken}`,
        },
      });

      expect(response.statusCode).toBe(200);

      const body = JSON.parse(response.body);
      expect(typeof body.data.remainingCodes).toBe('number');
    });
  });
});
