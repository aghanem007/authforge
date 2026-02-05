import type { FastifyInstance } from 'fastify';
import * as mfaService from '../services/mfa.service.js';
import * as auditService from '../services/audit.service.js';
import { authenticate, extractClientInfo } from '../middleware/auth.middleware.js';
import { authRateLimiter } from '../middleware/rateLimit.middleware.js';
import { mfaVerifySchema } from '../utils/validators.js';
import { AuditAction } from '../types/index.js';
import type { MfaVerifyInput } from '../utils/validators.js';

export async function mfaRoutes(fastify: FastifyInstance): Promise<void> {
  // All MFA routes require authentication
  fastify.addHook('preHandler', authenticate);

  // Setup MFA (get QR code and secret)
  fastify.post('/setup', async (request, reply) => {
    const result = await mfaService.setupMfa(request.user!.id);

    reply.send({
      success: true,
      data: {
        secret: result.secret,
        qrCode: result.qrCode,
        backupCodes: result.backupCodes,
        message: 'Scan the QR code with your authenticator app, then verify with a code',
      },
    });
  });

  // Verify and enable MFA
  fastify.post<{ Body: MfaVerifyInput }>(
    '/verify',
    {
      preHandler: [authRateLimiter],
    },
    async (request, reply) => {
      const data = mfaVerifySchema.parse(request.body);
      const { ipAddress, userAgent } = extractClientInfo(request);

      const success = await mfaService.verifyAndEnableMfa(
        request.user!.id,
        data.code
      );

      if (!success) {
        reply.code(400).send({
          success: false,
          error: {
            code: 'MFA_INVALID',
            message: 'Invalid verification code',
          },
        });
        return;
      }

      await auditService.logAuthEvent(AuditAction.MFA_ENABLED, {
        userId: request.user!.id,
        ipAddress,
        userAgent,
      });

      reply.send({
        success: true,
        data: {
          message: 'MFA enabled successfully',
        },
      });
    }
  );

  // Disable MFA
  fastify.post<{ Body: { password: string } }>(
    '/disable',
    {
      preHandler: [authRateLimiter],
    },
    async (request, reply) => {
      const { password } = request.body;
      const { ipAddress, userAgent } = extractClientInfo(request);

      await mfaService.disableMfa(request.user!.id, password);

      await auditService.logAuthEvent(AuditAction.MFA_DISABLED, {
        userId: request.user!.id,
        ipAddress,
        userAgent,
      });

      reply.send({
        success: true,
        data: {
          message: 'MFA disabled successfully',
        },
      });
    }
  );

  // Get backup codes count
  fastify.get('/backup-codes', async (request, reply) => {
    const count = await mfaService.getBackupCodesCount(request.user!.id);

    reply.send({
      success: true,
      data: {
        remainingCodes: count,
      },
    });
  });

  // Regenerate backup codes
  fastify.post<{ Body: { password: string } }>(
    '/regenerate-codes',
    {
      preHandler: [authRateLimiter],
    },
    async (request, reply) => {
      const { password } = request.body;

      const newCodes = await mfaService.regenerateBackupCodes(
        request.user!.id,
        password
      );

      reply.send({
        success: true,
        data: {
          backupCodes: newCodes,
          message: 'New backup codes generated. Store them securely.',
        },
      });
    }
  );
}
