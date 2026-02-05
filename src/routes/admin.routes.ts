import type { FastifyInstance } from 'fastify';
import * as userService from '../services/user.service.js';
import * as auditService from '../services/audit.service.js';
import { authenticate, extractClientInfo } from '../middleware/auth.middleware.js';
import { requireAdmin } from '../middleware/rbac.middleware.js';
import {
  paginationSchema,
  userIdParamSchema,
  roleAssignSchema,
  roleCreateSchema,
  auditLogQuerySchema,
} from '../utils/validators.js';

export async function adminRoutes(fastify: FastifyInstance): Promise<void> {
  // All admin routes require authentication and admin role
  fastify.addHook('preHandler', authenticate);
  fastify.addHook('preHandler', requireAdmin);

  // === User Management ===

  // List users
  fastify.get<{ Querystring: { page?: string; limit?: string; search?: string } }>(
    '/users',
    async (request, reply) => {
      const { page, limit } = paginationSchema.parse(request.query);
      const search = request.query.search;

      const result = await userService.getUsers(page, limit, search);

      reply.send({
        success: true,
        data: result,
      });
    }
  );

  // Get single user
  fastify.get<{ Params: { id: string } }>(
    '/users/:id',
    async (request, reply) => {
      const { id } = userIdParamSchema.parse(request.params);

      const user = await userService.getUserById(id);

      if (!user) {
        reply.code(404).send({
          success: false,
          error: {
            code: 'NOT_FOUND',
            message: 'User not found',
          },
        });
        return;
      }

      reply.send({
        success: true,
        data: { user },
      });
    }
  );

  // Update user
  fastify.patch<{
    Params: { id: string };
    Body: { emailVerified?: boolean; unlock?: boolean };
  }>(
    '/users/:id',
    async (request, reply) => {
      const { id } = userIdParamSchema.parse(request.params);
      const { emailVerified, unlock } = request.body;
      const { ipAddress, userAgent } = extractClientInfo(request);

      const updateData: { emailVerified?: boolean; lockedUntil?: null } = {};

      if (emailVerified !== undefined) {
        updateData.emailVerified = emailVerified;
      }

      if (unlock) {
        updateData.lockedUntil = null;
      }

      const user = await userService.updateUser(
        id,
        updateData,
        request.user!.id,
        ipAddress,
        userAgent
      );

      reply.send({
        success: true,
        data: { user },
      });
    }
  );

  // Delete user
  fastify.delete<{ Params: { id: string } }>(
    '/users/:id',
    async (request, reply) => {
      const { id } = userIdParamSchema.parse(request.params);
      const { ipAddress, userAgent } = extractClientInfo(request);

      // Prevent self-deletion
      if (id === request.user!.id) {
        reply.code(400).send({
          success: false,
          error: {
            code: 'INVALID_OPERATION',
            message: 'Cannot delete your own account',
          },
        });
        return;
      }

      await userService.deleteUser(id, request.user!.id, ipAddress, userAgent);

      reply.send({
        success: true,
        data: { message: 'User deleted' },
      });
    }
  );

  // Assign role to user
  fastify.post<{ Params: { id: string }; Body: { roleId: string } }>(
    '/users/:id/roles',
    async (request, reply) => {
      const { id } = userIdParamSchema.parse(request.params);
      const { roleId } = roleAssignSchema.parse(request.body);
      const { ipAddress, userAgent } = extractClientInfo(request);

      await userService.assignRole(
        id,
        roleId,
        request.user!.id,
        ipAddress,
        userAgent
      );

      reply.send({
        success: true,
        data: { message: 'Role assigned' },
      });
    }
  );

  // Remove role from user
  fastify.delete<{ Params: { id: string; roleId: string } }>(
    '/users/:id/roles/:roleId',
    async (request, reply) => {
      const { id } = userIdParamSchema.parse(request.params);
      const { roleId } = request.params;
      const { ipAddress, userAgent } = extractClientInfo(request);

      await userService.removeRole(
        id,
        roleId,
        request.user!.id,
        ipAddress,
        userAgent
      );

      reply.send({
        success: true,
        data: { message: 'Role removed' },
      });
    }
  );

  // === Role Management ===

  // List roles
  fastify.get('/roles', async (request, reply) => {
    const roles = await userService.getRoles();

    reply.send({
      success: true,
      data: { roles },
    });
  });

  // Create role
  fastify.post<{ Body: { name: string; description?: string; permissions?: string[] } }>(
    '/roles',
    async (request, reply) => {
      const data = roleCreateSchema.parse(request.body);

      const role = await userService.createRole(
        data.name,
        data.description,
        data.permissions
      );

      reply.code(201).send({
        success: true,
        data: { role },
      });
    }
  );

  // Delete role
  fastify.delete<{ Params: { id: string } }>(
    '/roles/:id',
    async (request, reply) => {
      const { id } = request.params;

      await userService.deleteRole(id);

      reply.send({
        success: true,
        data: { message: 'Role deleted' },
      });
    }
  );

  // === Permission Management ===

  // List permissions
  fastify.get('/permissions', async (request, reply) => {
    const permissions = await userService.getPermissions();

    reply.send({
      success: true,
      data: { permissions },
    });
  });

  // Create permission
  fastify.post<{ Body: { name: string; description?: string } }>(
    '/permissions',
    async (request, reply) => {
      const { name, description } = request.body;

      const permission = await userService.createPermission(name, description);

      reply.code(201).send({
        success: true,
        data: { permission },
      });
    }
  );

  // === Audit Logs ===

  // Query audit logs
  fastify.get<{
    Querystring: {
      userId?: string;
      action?: string;
      startDate?: string;
      endDate?: string;
      page?: string;
      limit?: string;
    };
  }>('/audit/logs', async (request, reply) => {
    const params = auditLogQuerySchema.parse(request.query);

    const result = await auditService.getAuditLogs(params);

    reply.send({
      success: true,
      data: result,
    });
  });

  // Export audit logs
  fastify.get<{
    Querystring: {
      userId?: string;
      action?: string;
      startDate?: string;
      endDate?: string;
    };
  }>('/audit/export', async (request, reply) => {
    const { userId, action, startDate, endDate } = request.query;

    const logs = await auditService.exportAuditLogs({
      userId,
      action,
      startDate: startDate ? new Date(startDate) : undefined,
      endDate: endDate ? new Date(endDate) : undefined,
    });

    reply.header('Content-Type', 'application/json');
    reply.header(
      'Content-Disposition',
      `attachment; filename="audit-logs-${new Date().toISOString()}.json"`
    );

    reply.send(logs);
  });
}
