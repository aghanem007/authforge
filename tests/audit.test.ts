import { describe, it, expect, beforeAll } from 'vitest';
import { buildApp } from '../src/app.js';
import type { FastifyInstance } from 'fastify';

describe('Audit Routes', () => {
  let app: FastifyInstance;
  let accessToken: string;

  beforeAll(async () => {
    app = await buildApp();

    // Register — this generates audit events automatically
    const res = await app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: {
        email: 'audit-user@example.com',
        password: 'SecureP@ss123!',
      },
    });

    accessToken = JSON.parse(res.body).data.tokens.accessToken;

    // Login a couple times to generate more audit events
    await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: {
        email: 'audit-user@example.com',
        password: 'SecureP@ss123!',
      },
    });
  });

  describe('GET /audit/my-activity', () => {
    it('should return user activity logs', async () => {
      const response = await app.inject({
        method: 'GET',
        url: '/audit/my-activity',
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expect(response.statusCode).toBe(200);

      const body = JSON.parse(response.body);
      expect(body.success).toBe(true);
      expect(Array.isArray(body.data.items)).toBe(true);
      expect(body.data.items.length).toBeGreaterThanOrEqual(1);
      expect(body.data.pagination).toBeDefined();
    });

    it('should support pagination', async () => {
      const response = await app.inject({
        method: 'GET',
        url: '/audit/my-activity?page=1&limit=1',
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expect(response.statusCode).toBe(200);

      const body = JSON.parse(response.body);
      expect(body.data.items.length).toBeLessThanOrEqual(1);
      expect(body.data.pagination.limit).toBe(1);
    });

    it('should reject unauthenticated requests', async () => {
      const response = await app.inject({
        method: 'GET',
        url: '/audit/my-activity',
      });

      expect(response.statusCode).toBe(401);
    });
  });

  describe('GET /audit/security-alerts', () => {
    it('should return security alerts', async () => {
      // Trigger a failed login to generate a security alert
      await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: {
          email: 'audit-user@example.com',
          password: 'wrongpassword',
        },
      });

      const response = await app.inject({
        method: 'GET',
        url: '/audit/security-alerts',
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expect(response.statusCode).toBe(200);

      const body = JSON.parse(response.body);
      expect(body.success).toBe(true);
      expect(Array.isArray(body.data.alerts)).toBe(true);
    });

    it('should accept days parameter', async () => {
      const response = await app.inject({
        method: 'GET',
        url: '/audit/security-alerts?days=30',
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expect(response.statusCode).toBe(200);
    });
  });
});
