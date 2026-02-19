import { describe, it, expect, beforeAll } from 'vitest';
import { buildApp } from '../src/app.js';
import type { FastifyInstance } from 'fastify';

describe('Session Routes', () => {
  let app: FastifyInstance;
  let accessToken: string;
  let refreshToken: string;

  beforeAll(async () => {
    app = await buildApp();

    // Register and login to get tokens
    const res = await app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: {
        email: 'session-user@example.com',
        password: 'SecureP@ss123!',
      },
    });

    const data = JSON.parse(res.body).data;
    accessToken = data.tokens.accessToken;
    refreshToken = data.tokens.refreshToken;
  });

  describe('GET /sessions', () => {
    it('should list active sessions', async () => {
      const response = await app.inject({
        method: 'GET',
        url: '/sessions',
        headers: {
          authorization: `Bearer ${accessToken}`,
        },
      });

      expect(response.statusCode).toBe(200);

      const body = JSON.parse(response.body);
      expect(body.success).toBe(true);
      expect(Array.isArray(body.data.sessions)).toBe(true);
      expect(body.data.sessions.length).toBeGreaterThanOrEqual(1);
    });

    it('should reject unauthenticated requests', async () => {
      const response = await app.inject({
        method: 'GET',
        url: '/sessions',
      });

      expect(response.statusCode).toBe(401);
    });
  });

  describe('DELETE /sessions/:id', () => {
    it('should revoke a session by id', async () => {
      // Create a second session by logging in again
      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: {
          email: 'session-user@example.com',
          password: 'SecureP@ss123!',
        },
      });

      const loginData = JSON.parse(loginRes.body).data;
      const secondToken = loginData.tokens.accessToken;

      // List sessions to get an ID
      const listRes = await app.inject({
        method: 'GET',
        url: '/sessions',
        headers: { authorization: `Bearer ${secondToken}` },
      });

      const sessions = JSON.parse(listRes.body).data.sessions;
      expect(sessions.length).toBeGreaterThanOrEqual(2);

      // Revoke the first session
      const targetId = sessions[sessions.length - 1].id;
      const deleteRes = await app.inject({
        method: 'DELETE',
        url: `/sessions/${targetId}`,
        headers: { authorization: `Bearer ${secondToken}` },
      });

      expect(deleteRes.statusCode).toBe(200);
      expect(JSON.parse(deleteRes.body).success).toBe(true);
    });

    it('should return 404 for non-existent session', async () => {
      // Login fresh to have a valid token
      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: {
          email: 'session-user@example.com',
          password: 'SecureP@ss123!',
        },
      });
      const token = JSON.parse(loginRes.body).data.tokens.accessToken;

      const response = await app.inject({
        method: 'DELETE',
        url: '/sessions/clxxxxxxxxxxxxxxxxxxxxxxxxx',
        headers: { authorization: `Bearer ${token}` },
      });

      expect(response.statusCode).toBe(404);
    });
  });

  describe('GET /sessions/devices', () => {
    it('should list user devices', async () => {
      // Login to create a device entry
      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: {
          email: 'session-user@example.com',
          password: 'SecureP@ss123!',
        },
      });
      const token = JSON.parse(loginRes.body).data.tokens.accessToken;

      const response = await app.inject({
        method: 'GET',
        url: '/sessions/devices',
        headers: { authorization: `Bearer ${token}` },
      });

      expect(response.statusCode).toBe(200);

      const body = JSON.parse(response.body);
      expect(Array.isArray(body.data.devices)).toBe(true);
    });
  });
});
