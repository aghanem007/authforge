import type { FastifyInstance } from 'fastify';
import * as sessionService from '../services/session.service.js';
import * as auditService from '../services/audit.service.js';
import { authenticate, extractClientInfo } from '../middleware/auth.middleware.js';
import { sessionIdParamSchema, deviceIdParamSchema } from '../utils/validators.js';
import { AuditAction } from '../types/index.js';

export async function sessionRoutes(fastify: FastifyInstance): Promise<void> {
  // All session routes require authentication
  fastify.addHook('preHandler', authenticate);

  // List active sessions
  fastify.get('/', async (request, reply) => {
    // Get current session ID from refresh token if available
    const sessions = await sessionService.getUserSessions(request.user!.id);

    reply.send({
      success: true,
      data: { sessions },
    });
  });

  // Revoke a specific session
  fastify.delete<{ Params: { id: string } }>(
    '/:id',
    async (request, reply) => {
      const { id } = sessionIdParamSchema.parse(request.params);
      const { ipAddress, userAgent } = extractClientInfo(request);

      // Verify session belongs to user
      const session = await sessionService.getSessionById(id);

      if (!session || session.userId !== request.user!.id) {
        reply.code(404).send({
          success: false,
          error: {
            code: 'NOT_FOUND',
            message: 'Session not found',
          },
        });
        return;
      }

      await sessionService.deleteSession(id);

      await auditService.logAuthEvent(AuditAction.SESSION_REVOKED, {
        userId: request.user!.id,
        ipAddress,
        userAgent,
        metadata: { sessionId: id },
      });

      reply.send({
        success: true,
        data: { message: 'Session revoked' },
      });
    }
  );

  // List user's devices
  fastify.get('/devices', async (request, reply) => {
    const devices = await sessionService.getUserDevices(request.user!.id);

    reply.send({
      success: true,
      data: { devices },
    });
  });

  // Trust a device
  fastify.post<{ Params: { id: string } }>(
    '/devices/:id/trust',
    async (request, reply) => {
      const { id } = deviceIdParamSchema.parse(request.params);
      const { ipAddress, userAgent } = extractClientInfo(request);

      const device = await sessionService.trustDevice(id, request.user!.id);

      await auditService.logAuthEvent(AuditAction.DEVICE_TRUSTED, {
        userId: request.user!.id,
        ipAddress,
        userAgent,
        metadata: { deviceId: id, deviceName: device.name },
      });

      reply.send({
        success: true,
        data: {
          message: 'Device trusted',
          device: {
            id: device.id,
            name: device.name,
            trusted: device.trusted,
          },
        },
      });
    }
  );

  // Untrust a device
  fastify.post<{ Params: { id: string } }>(
    '/devices/:id/untrust',
    async (request, reply) => {
      const { id } = deviceIdParamSchema.parse(request.params);
      const { ipAddress, userAgent } = extractClientInfo(request);

      const device = await sessionService.untrustDevice(id, request.user!.id);

      await auditService.logAuthEvent(AuditAction.DEVICE_UNTRUSTED, {
        userId: request.user!.id,
        ipAddress,
        userAgent,
        metadata: { deviceId: id, deviceName: device.name },
      });

      reply.send({
        success: true,
        data: {
          message: 'Device untrusted',
          device: {
            id: device.id,
            name: device.name,
            trusted: device.trusted,
          },
        },
      });
    }
  );

  // Delete a device
  fastify.delete<{ Params: { id: string } }>(
    '/devices/:id',
    async (request, reply) => {
      const { id } = deviceIdParamSchema.parse(request.params);

      await sessionService.deleteDevice(id, request.user!.id);

      reply.send({
        success: true,
        data: { message: 'Device removed' },
      });
    }
  );
}
