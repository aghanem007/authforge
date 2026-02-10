import type { FastifyInstance } from 'fastify';
import * as apiKeyService from '../services/apikey.service.js';
import * as auditService from '../services/audit.service.js';
import { authenticate, extractClientInfo } from '../middleware/auth.middleware.js';
import { createApiKeySchema, apiKeyIdParamSchema } from '../utils/validators.js';
import { AuditAction } from '../types/index.js';

export async function apiKeyRoutes(fastify: FastifyInstance): Promise<void> {
  // All API key routes require authentication
  fastify.addHook('preHandler', authenticate);

  // Create a new API key
  fastify.post('/', async (request, reply) => {
    const { name, permissions, expiresInDays } = createApiKeySchema.parse(request.body);
    const { ipAddress, userAgent } = extractClientInfo(request);

    const expiresAt = expiresInDays
      ? new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000)
      : undefined;

    const { apiKey, rawKey } = await apiKeyService.createApiKey(
      request.user!.id,
      name,
      permissions,
      expiresAt
    );

    await auditService.logAuthEvent(AuditAction.API_KEY_CREATED, {
      userId: request.user!.id,
      ipAddress,
      userAgent,
      metadata: { keyName: name, keyPrefix: apiKey.keyPrefix },
    });

    reply.code(201).send({
      success: true,
      data: {
        apiKey,
        rawKey,
        message: 'Store this key securely — it will not be shown again',
      },
    });
  });

  // List all API keys for the user
  fastify.get('/', async (request, reply) => {
    const keys = await apiKeyService.listApiKeys(request.user!.id);

    reply.send({
      success: true,
      data: { apiKeys: keys },
    });
  });

  // Get a specific API key
  fastify.get<{ Params: { id: string } }>('/:id', async (request, reply) => {
    const { id } = apiKeyIdParamSchema.parse(request.params);

    const apiKey = await apiKeyService.getApiKeyById(id, request.user!.id);

    if (!apiKey) {
      reply.code(404).send({
        success: false,
        error: {
          code: 'NOT_FOUND',
          message: 'API key not found',
        },
      });
      return;
    }

    reply.send({
      success: true,
      data: { apiKey },
    });
  });

  // Revoke an API key
  fastify.post<{ Params: { id: string } }>('/:id/revoke', async (request, reply) => {
    const { id } = apiKeyIdParamSchema.parse(request.params);
    const { ipAddress, userAgent } = extractClientInfo(request);

    const apiKey = await apiKeyService.revokeApiKey(id, request.user!.id);

    if (!apiKey) {
      reply.code(404).send({
        success: false,
        error: {
          code: 'NOT_FOUND',
          message: 'API key not found',
        },
      });
      return;
    }

    await auditService.logAuthEvent(AuditAction.API_KEY_REVOKED, {
      userId: request.user!.id,
      ipAddress,
      userAgent,
      metadata: { keyName: apiKey.name, keyPrefix: apiKey.keyPrefix },
    });

    reply.send({
      success: true,
      data: {
        apiKey,
        message: 'API key revoked',
      },
    });
  });

  // Delete an API key permanently
  fastify.delete<{ Params: { id: string } }>('/:id', async (request, reply) => {
    const { id } = apiKeyIdParamSchema.parse(request.params);

    const deleted = await apiKeyService.deleteApiKey(id, request.user!.id);

    if (!deleted) {
      reply.code(404).send({
        success: false,
        error: {
          code: 'NOT_FOUND',
          message: 'API key not found',
        },
      });
      return;
    }

    reply.send({
      success: true,
      data: { message: 'API key deleted' },
    });
  });
}
