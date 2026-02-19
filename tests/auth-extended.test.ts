import { describe, it, expect, beforeAll } from 'vitest';
import { buildApp } from '../src/app.js';
import type { FastifyInstance } from 'fastify';

describe('Auth Routes — Extended', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await buildApp();
  });

  describe('POST /auth/logout', () => {
    it('should logout and invalidate the session', async () => {
      const regRes = await app.inject({
        method: 'POST',
        url: '/auth/register',
        payload: {
          email: 'logout@example.com',
          password: 'SecureP@ss123!',
        },
      });

      const { tokens } = JSON.parse(regRes.body).data;

      const response = await app.inject({
        method: 'POST',
        url: '/auth/logout',
        headers: { authorization: `Bearer ${tokens.accessToken}` },
        payload: { refreshToken: tokens.refreshToken },
      });

      expect(response.statusCode).toBe(200);
      expect(JSON.parse(response.body).success).toBe(true);
    });

    it('should reject logout without auth', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/auth/logout',
        payload: { refreshToken: 'whatever' },
      });

      expect(response.statusCode).toBe(401);
    });
  });

  describe('POST /auth/logout-all', () => {
    it('should revoke all sessions', async () => {
      const regRes = await app.inject({
        method: 'POST',
        url: '/auth/register',
        payload: {
          email: 'logoutall@example.com',
          password: 'SecureP@ss123!',
        },
      });

      const { tokens } = JSON.parse(regRes.body).data;

      // Login again to create a second session
      await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: {
          email: 'logoutall@example.com',
          password: 'SecureP@ss123!',
        },
      });

      const response = await app.inject({
        method: 'POST',
        url: '/auth/logout-all',
        headers: { authorization: `Bearer ${tokens.accessToken}` },
      });

      expect(response.statusCode).toBe(200);

      const body = JSON.parse(response.body);
      expect(body.data.sessionsRevoked).toBeGreaterThanOrEqual(2);
    });
  });

  describe('POST /auth/change-password', () => {
    it('should change password with valid current password', async () => {
      const regRes = await app.inject({
        method: 'POST',
        url: '/auth/register',
        payload: {
          email: 'changepw@example.com',
          password: 'SecureP@ss123!',
        },
      });

      const { tokens } = JSON.parse(regRes.body).data;

      const response = await app.inject({
        method: 'POST',
        url: '/auth/change-password',
        headers: { authorization: `Bearer ${tokens.accessToken}` },
        payload: {
          currentPassword: 'SecureP@ss123!',
          newPassword: 'NewSecureP@ss456!',
        },
      });

      expect(response.statusCode).toBe(200);

      // Verify new password works
      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: {
          email: 'changepw@example.com',
          password: 'NewSecureP@ss456!',
        },
      });

      expect(loginRes.statusCode).toBe(200);
    });

    it('should reject with wrong current password', async () => {
      const regRes = await app.inject({
        method: 'POST',
        url: '/auth/register',
        payload: {
          email: 'changepw2@example.com',
          password: 'SecureP@ss123!',
        },
      });

      const { tokens } = JSON.parse(regRes.body).data;

      const response = await app.inject({
        method: 'POST',
        url: '/auth/change-password',
        headers: { authorization: `Bearer ${tokens.accessToken}` },
        payload: {
          currentPassword: 'WrongPassword123!',
          newPassword: 'NewSecureP@ss456!',
        },
      });

      expect(response.statusCode).toBe(401);
    });
  });

  describe('POST /auth/forgot-password', () => {
    it('should accept request for existing email', async () => {
      await app.inject({
        method: 'POST',
        url: '/auth/register',
        payload: {
          email: 'forgot@example.com',
          password: 'SecureP@ss123!',
        },
      });

      const response = await app.inject({
        method: 'POST',
        url: '/auth/forgot-password',
        payload: { email: 'forgot@example.com' },
      });

      expect(response.statusCode).toBe(200);
      expect(JSON.parse(response.body).success).toBe(true);
    });

    it('should not reveal non-existent email', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/auth/forgot-password',
        payload: { email: 'nonexistent@example.com' },
      });

      // Should still return 200 to prevent enumeration
      expect(response.statusCode).toBe(200);
      expect(JSON.parse(response.body).success).toBe(true);
    });
  });

  describe('GET /health', () => {
    it('should return healthy status', async () => {
      const response = await app.inject({
        method: 'GET',
        url: '/health',
      });

      expect(response.statusCode).toBe(200);

      const body = JSON.parse(response.body);
      expect(body.status).toBe('healthy');
      expect(body.version).toBe('1.0.0');
    });
  });
});
