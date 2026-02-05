import type { FastifyInstance } from 'fastify';
import * as auditService from '../services/audit.service.js';
import { authenticate } from '../middleware/auth.middleware.js';
import { paginationSchema } from '../utils/validators.js';

export async function auditRoutes(fastify: FastifyInstance): Promise<void> {
  // All audit routes require authentication
  fastify.addHook('preHandler', authenticate);

  // Get user's own activity logs
  fastify.get<{
    Querystring: { page?: string; limit?: string };
  }>('/my-activity', async (request, reply) => {
    const { page, limit } = paginationSchema.parse(request.query);

    const result = await auditService.getUserActivityLogs(
      request.user!.id,
      page,
      limit
    );

    reply.send({
      success: true,
      data: result,
    });
  });

  // Get security alerts for current user
  fastify.get<{
    Querystring: { days?: string };
  }>('/security-alerts', async (request, reply) => {
    const days = request.query.days ? parseInt(request.query.days, 10) : 7;

    const alerts = await auditService.getSecurityAlerts(
      request.user!.id,
      days
    );

    reply.send({
      success: true,
      data: { alerts },
    });
  });
}
