import type { FastifyRequest, FastifyReply } from 'fastify';
import { ErrorCode } from '../types/index.js';

export function requireRoles(...requiredRoles: string[]) {
  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    if (!request.user) {
      reply.code(401).send({
        success: false,
        error: {
          code: ErrorCode.UNAUTHORIZED,
          message: 'Authentication required',
        },
      });
      return;
    }

    const hasRole = requiredRoles.some((role) =>
      request.user!.roles.includes(role)
    );

    if (!hasRole) {
      reply.code(403).send({
        success: false,
        error: {
          code: ErrorCode.FORBIDDEN,
          message: 'Insufficient permissions',
        },
      });
    }
  };
}

export function requirePermissions(...requiredPermissions: string[]) {
  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    if (!request.user) {
      reply.code(401).send({
        success: false,
        error: {
          code: ErrorCode.UNAUTHORIZED,
          message: 'Authentication required',
        },
      });
      return;
    }

    const hasAllPermissions = requiredPermissions.every((permission) =>
      request.user!.permissions.includes(permission)
    );

    if (!hasAllPermissions) {
      reply.code(403).send({
        success: false,
        error: {
          code: ErrorCode.FORBIDDEN,
          message: 'Insufficient permissions',
        },
      });
    }
  };
}

export function requireAnyPermission(...permissions: string[]) {
  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    if (!request.user) {
      reply.code(401).send({
        success: false,
        error: {
          code: ErrorCode.UNAUTHORIZED,
          message: 'Authentication required',
        },
      });
      return;
    }

    const hasAnyPermission = permissions.some((permission) =>
      request.user!.permissions.includes(permission)
    );

    if (!hasAnyPermission) {
      reply.code(403).send({
        success: false,
        error: {
          code: ErrorCode.FORBIDDEN,
          message: 'Insufficient permissions',
        },
      });
    }
  };
}

// Check if user is admin
export async function requireAdmin(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  return requireRoles('admin')(request, reply);
}

// Check if user owns the resource or is admin
export function requireOwnerOrAdmin(userIdParam: string = 'id') {
  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    if (!request.user) {
      reply.code(401).send({
        success: false,
        error: {
          code: ErrorCode.UNAUTHORIZED,
          message: 'Authentication required',
        },
      });
      return;
    }

    const params = request.params as Record<string, string>;
    const resourceUserId = params[userIdParam];

    const isOwner = request.user.id === resourceUserId;
    const isAdmin = request.user.roles.includes('admin');

    if (!isOwner && !isAdmin) {
      reply.code(403).send({
        success: false,
        error: {
          code: ErrorCode.FORBIDDEN,
          message: 'Access denied',
        },
      });
    }
  };
}
