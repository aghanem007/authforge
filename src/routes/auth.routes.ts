import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import * as authService from '../services/auth.service.js';
import { authenticate, extractClientInfo } from '../middleware/auth.middleware.js';
import { loginRateLimiter, authRateLimiter, passwordResetRateLimiter } from '../middleware/rateLimit.middleware.js';
import {
  registerSchema,
  loginSchema,
  refreshTokenSchema,
  changePasswordSchema,
  passwordResetRequestSchema,
  passwordResetSchema,
  mfaVerifySchema,
} from '../utils/validators.js';
import type { RegisterInput, LoginInput, RefreshTokenInput, ChangePasswordInput, PasswordResetRequestInput, PasswordResetInput, MfaVerifyInput } from '../utils/validators.js';

export async function authRoutes(fastify: FastifyInstance): Promise<void> {
  // Register
  fastify.post<{ Body: RegisterInput }>(
    '/register',
    {
      preHandler: [authRateLimiter],
    },
    async (request, reply) => {
      const data = registerSchema.parse(request.body);
      const { ipAddress, userAgent } = extractClientInfo(request);

      const result = await authService.register(
        data.email,
        data.password,
        ipAddress,
        userAgent
      );

      reply.code(201).send({
        success: true,
        data: result,
      });
    }
  );

  // Login
  fastify.post<{ Body: LoginInput }>(
    '/login',
    {
      preHandler: [loginRateLimiter],
    },
    async (request, reply) => {
      const data = loginSchema.parse(request.body);
      const { ipAddress, userAgent } = extractClientInfo(request);

      const result = await authService.login(
        data.email,
        data.password,
        ipAddress,
        userAgent,
        data.mfaCode,
        data.deviceFingerprint
      );

      if (result.requiresMfa) {
        reply.code(200).send({
          success: true,
          data: {
            requiresMfa: true,
            mfaChallengeId: result.mfaChallengeId,
          },
        });
        return;
      }

      reply.send({
        success: true,
        data: {
          user: result.user,
          tokens: result.tokens,
        },
      });
    }
  );

  // Complete MFA login
  fastify.post<{ Body: { challengeId: string; code: string } }>(
    '/login/mfa',
    {
      preHandler: [authRateLimiter],
    },
    async (request, reply) => {
      const { challengeId, code } = request.body;
      const parsedCode = mfaVerifySchema.parse({ code });
      const { ipAddress, userAgent } = extractClientInfo(request);

      const result = await authService.completeMfaLogin(
        challengeId,
        parsedCode.code,
        ipAddress,
        userAgent
      );

      reply.send({
        success: true,
        data: result,
      });
    }
  );

  // Refresh tokens
  fastify.post<{ Body: RefreshTokenInput }>(
    '/refresh',
    async (request, reply) => {
      const data = refreshTokenSchema.parse(request.body);
      const { ipAddress, userAgent } = extractClientInfo(request);

      const tokens = await authService.refreshTokens(
        data.refreshToken,
        ipAddress,
        userAgent
      );

      reply.send({
        success: true,
        data: { tokens },
      });
    }
  );

  // Logout
  fastify.post<{ Body: { refreshToken: string } }>(
    '/logout',
    {
      preHandler: [authenticate],
    },
    async (request, reply) => {
      const { refreshToken } = request.body;
      const { ipAddress, userAgent } = extractClientInfo(request);

      await authService.logout(
        refreshToken,
        request.jti!,
        ipAddress,
        userAgent
      );

      reply.send({
        success: true,
        data: { message: 'Logged out successfully' },
      });
    }
  );

  // Logout all devices
  fastify.post(
    '/logout-all',
    {
      preHandler: [authenticate],
    },
    async (request, reply) => {
      const { ipAddress, userAgent } = extractClientInfo(request);

      const count = await authService.logoutAll(
        request.user!.id,
        ipAddress,
        userAgent
      );

      reply.send({
        success: true,
        data: {
          message: 'Logged out from all devices',
          sessionsRevoked: count,
        },
      });
    }
  );

  // Change password
  fastify.post<{ Body: ChangePasswordInput }>(
    '/change-password',
    {
      preHandler: [authenticate, authRateLimiter],
    },
    async (request, reply) => {
      const data = changePasswordSchema.parse(request.body);
      const { ipAddress, userAgent } = extractClientInfo(request);

      await authService.changePassword(
        request.user!.id,
        data.currentPassword,
        data.newPassword,
        ipAddress,
        userAgent
      );

      reply.send({
        success: true,
        data: { message: 'Password changed successfully' },
      });
    }
  );

  // Request password reset
  fastify.post<{ Body: PasswordResetRequestInput }>(
    '/forgot-password',
    {
      preHandler: [passwordResetRateLimiter],
    },
    async (request, reply) => {
      const data = passwordResetRequestSchema.parse(request.body);
      const { ipAddress, userAgent } = extractClientInfo(request);

      const token = await authService.requestPasswordReset(
        data.email,
        ipAddress,
        userAgent
      );

      // Always return success to prevent email enumeration
      // In production, you'd send an email with the token
      if (token) {
        console.log(`Password reset token for ${data.email}: ${token}`);
      }

      reply.send({
        success: true,
        data: {
          message: 'If an account exists with that email, a reset link has been sent',
        },
      });
    }
  );

  // Reset password
  fastify.post<{ Body: PasswordResetInput }>(
    '/reset-password',
    {
      preHandler: [authRateLimiter],
    },
    async (request, reply) => {
      const data = passwordResetSchema.parse(request.body);
      const { ipAddress, userAgent } = extractClientInfo(request);

      await authService.resetPassword(
        data.token,
        data.password,
        ipAddress,
        userAgent
      );

      reply.send({
        success: true,
        data: { message: 'Password reset successfully' },
      });
    }
  );

  // Get current user
  fastify.get(
    '/me',
    {
      preHandler: [authenticate],
    },
    async (request, reply) => {
      reply.send({
        success: true,
        data: {
          user: request.user,
        },
      });
    }
  );
}
