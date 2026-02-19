import { describe, it, expect, beforeAll } from 'vitest';
import { buildApp } from '../src/app.js';
import type { FastifyInstance } from 'fastify';

describe('API Key Routes', () => {
  let app: FastifyInstance;
  let accessToken: string;

  beforeAll(async () => {
    app = await buildApp();

    const res = await app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: {
        email: 'apikey-user@example.com',
        password: 'SecureP@ss123!',
      },
    });

    accessToken = JSON.parse(res.body).data.tokens.accessToken;
  });

  describe('POST /api-keys', () => {
    it('should create a new API key', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/api-keys',
        headers: { authorization: `Bearer ${accessToken}` },
        payload: {
          name: 'Test Key',
          permissions: ['read', 'write'],
        },
      });

      expect(response.statusCode).toBe(201);

      const body = JSON.parse(response.body);
      expect(body.success).toBe(true);
      expect(body.data.rawKey).toBeDefined();
      expect(body.data.rawKey).toMatch(/^af_/);
      expect(body.data.apiKey.name).toBe('Test Key');
    });

    it('should create a key with expiration', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/api-keys',
        headers: { authorization: `Bearer ${accessToken}` },
        payload: {
          name: 'Expiring Key',
          permissions: [],
          expiresInDays: 30,
        },
      });

      expect(response.statusCode).toBe(201);

      const body = JSON.parse(response.body);
      expect(body.data.apiKey.expiresAt).toBeDefined();
    });

    it('should reject without auth', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/api-keys',
        payload: { name: 'No Auth Key' },
      });

      expect(response.statusCode).toBe(401);
    });
  });

  describe('GET /api-keys', () => {
    it('should list user API keys', async () => {
      // Create a key first
      await app.inject({
        method: 'POST',
        url: '/api-keys',
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { name: 'Listed Key' },
      });

      const response = await app.inject({
        method: 'GET',
        url: '/api-keys',
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expect(response.statusCode).toBe(200);

      const body = JSON.parse(response.body);
      expect(Array.isArray(body.data.apiKeys)).toBe(true);
      expect(body.data.apiKeys.length).toBeGreaterThanOrEqual(1);
    });

    it('should not expose raw key in list', async () => {
      const response = await app.inject({
        method: 'GET',
        url: '/api-keys',
        headers: { authorization: `Bearer ${accessToken}` },
      });

      const body = JSON.parse(response.body);
      for (const key of body.data.apiKeys) {
        expect(key.keyHash).toBeUndefined();
      }
    });
  });

  describe('POST /api-keys/:id/revoke', () => {
    it('should revoke an API key', async () => {
      // Create a key
      const createRes = await app.inject({
        method: 'POST',
        url: '/api-keys',
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { name: 'To Revoke' },
      });
      const keyId = JSON.parse(createRes.body).data.apiKey.id;

      // Revoke it
      const response = await app.inject({
        method: 'POST',
        url: `/api-keys/${keyId}/revoke`,
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expect(response.statusCode).toBe(200);
      expect(JSON.parse(response.body).data.apiKey.revokedAt).toBeDefined();
    });
  });

  describe('DELETE /api-keys/:id', () => {
    it('should delete an API key permanently', async () => {
      // Create a key
      const createRes = await app.inject({
        method: 'POST',
        url: '/api-keys',
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { name: 'To Delete' },
      });
      const keyId = JSON.parse(createRes.body).data.apiKey.id;

      // Delete it
      const response = await app.inject({
        method: 'DELETE',
        url: `/api-keys/${keyId}`,
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expect(response.statusCode).toBe(200);

      // Verify it's gone
      const getRes = await app.inject({
        method: 'GET',
        url: `/api-keys/${keyId}`,
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expect(getRes.statusCode).toBe(404);
    });
  });
});
