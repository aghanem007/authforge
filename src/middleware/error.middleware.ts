import type { FastifyError, FastifyRequest, FastifyReply } from 'fastify';
import { ZodError } from 'zod';
import { ErrorCode } from '../types/index.js';

export function errorHandler(
  error: FastifyError,
  request: FastifyRequest,
  reply: FastifyReply
): void {
  // Log error for debugging
  console.error('Error:', {
    message: error.message,
    code: error.code,
    stack: process.env['NODE_ENV'] === 'development' ? error.stack : undefined,
  });

  // Handle Zod validation errors
  if (error instanceof ZodError) {
    reply.code(400).send({
      success: false,
      error: {
        code: ErrorCode.VALIDATION_ERROR,
        message: 'Validation failed',
        details: {
          errors: error.errors.map((e) => ({
            path: e.path.join('.'),
            message: e.message,
          })),
        },
      },
    });
    return;
  }

  // Handle known error codes
  const errorWithCode = error as Error & { code?: string };
  if (errorWithCode.code && Object.values(ErrorCode).includes(errorWithCode.code as ErrorCode)) {
    const statusCode = getStatusCodeForError(errorWithCode.code as ErrorCode);
    reply.code(statusCode).send({
      success: false,
      error: {
        code: errorWithCode.code,
        message: error.message,
      },
    });
    return;
  }

  // Handle Prisma errors
  if (error.name === 'PrismaClientKnownRequestError') {
    const prismaError = error as FastifyError & { code: string };
    if (prismaError.code === 'P2002') {
      reply.code(409).send({
        success: false,
        error: {
          code: ErrorCode.EMAIL_EXISTS,
          message: 'Resource already exists',
        },
      });
      return;
    }
    if (prismaError.code === 'P2025') {
      reply.code(404).send({
        success: false,
        error: {
          code: ErrorCode.NOT_FOUND,
          message: 'Resource not found',
        },
      });
      return;
    }
  }

  // Default error response
  const statusCode = error.statusCode ?? 500;
  const message = statusCode === 500 && process.env['NODE_ENV'] === 'production'
    ? 'Internal server error'
    : error.message;

  reply.code(statusCode).send({
    success: false,
    error: {
      code: statusCode === 500 ? ErrorCode.INTERNAL_ERROR : 'UNKNOWN_ERROR',
      message,
    },
  });
}

function getStatusCodeForError(code: ErrorCode): number {
  switch (code) {
    case ErrorCode.INVALID_CREDENTIALS:
    case ErrorCode.TOKEN_INVALID:
    case ErrorCode.TOKEN_EXPIRED:
    case ErrorCode.UNAUTHORIZED:
      return 401;
    case ErrorCode.FORBIDDEN:
    case ErrorCode.MFA_REQUIRED:
      return 403;
    case ErrorCode.NOT_FOUND:
      return 404;
    case ErrorCode.EMAIL_EXISTS:
      return 409;
    case ErrorCode.VALIDATION_ERROR:
    case ErrorCode.WEAK_PASSWORD:
    case ErrorCode.MFA_INVALID:
      return 400;
    case ErrorCode.RATE_LIMITED:
    case ErrorCode.ACCOUNT_LOCKED:
      return 429;
    default:
      return 500;
  }
}

export function notFoundHandler(
  request: FastifyRequest,
  reply: FastifyReply
): void {
  reply.code(404).send({
    success: false,
    error: {
      code: ErrorCode.NOT_FOUND,
      message: `Route ${request.method} ${request.url} not found`,
    },
  });
}
