import type { FastifyRequest, FastifyReply } from 'fastify';
import { verifyAccessToken } from '../services/token.service.js';
import { getUserRolesAndPermissions } from '../services/auth.service.js';
import type { AuthUser, AuthenticatedRequest } from '../types/index.js';
import { ErrorCode } from '../types/index.js';

declare module 'fastify' {
  interface FastifyRequest {
    user?: AuthUser;
    jti?: string;
  }
}

export async function authenticate(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  const authHeader = request.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    reply.code(401).send({
      success: false,
      error: {
        code: ErrorCode.UNAUTHORIZED,
        message: 'Missing or invalid authorization header',
      },
    });
    return;
  }

  const token = authHeader.slice(7);

  try {
    const payload = await verifyAccessToken(token);

    request.user = {
      id: payload.sub,
      email: payload.email,
      emailVerified: true, // JWT holder is assumed verified
      mfaEnabled: false, // Would need to fetch from DB if needed
      roles: payload.roles,
      permissions: payload.permissions,
    };
    request.jti = payload.jti;
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Invalid token';

    reply.code(401).send({
      success: false,
      error: {
        code: ErrorCode.TOKEN_INVALID,
        message,
      },
    });
  }
}

export function requireAuth(
  request: FastifyRequest,
  reply: FastifyReply,
  done: () => void
): void {
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
  done();
}

export function extractClientInfo(request: FastifyRequest): {
  ipAddress: string;
  userAgent: string;
} {
  // Get IP from various headers (for proxied requests)
  const forwarded = request.headers['x-forwarded-for'];
  const ipAddress = typeof forwarded === 'string'
    ? forwarded.split(',')[0]?.trim() ?? request.ip
    : request.ip;

  const userAgent = request.headers['user-agent'] ?? 'unknown';

  return { ipAddress, userAgent };
}

export async function optionalAuth(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  const authHeader = request.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return;
  }

  const token = authHeader.slice(7);

  try {
    const payload = await verifyAccessToken(token);

    request.user = {
      id: payload.sub,
      email: payload.email,
      emailVerified: true,
      mfaEnabled: false,
      roles: payload.roles,
      permissions: payload.permissions,
    };
    request.jti = payload.jti;
  } catch {
    // Ignore invalid tokens for optional auth
  }
}
