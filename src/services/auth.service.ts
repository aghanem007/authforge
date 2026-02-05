import { getPrismaClient } from '../config/database.js';
import { getRedisClient, RedisKeys, RedisTTL } from '../config/redis.js';
import { config } from '../config/index.js';
import { hashPassword, verifyPassword, checkPasswordStrength, validatePasswordRequirements } from '../utils/password.js';
import { generateSecureToken, hashToken, generateDeviceFingerprint } from '../utils/crypto.js';
import * as tokenService from './token.service.js';
import * as sessionService from './session.service.js';
import * as mfaService from './mfa.service.js';
import * as auditService from './audit.service.js';
import { AuditAction, ErrorCode, type TokenPair, type AuthUser } from '../types/index.js';
import type { User } from '@prisma/client';

const prisma = getPrismaClient();

export interface RegisterResult {
  user: {
    id: string;
    email: string;
  };
  tokens: TokenPair;
}

export interface LoginResult {
  requiresMfa: boolean;
  mfaChallengeId?: string;
  user?: AuthUser;
  tokens?: TokenPair;
}

export async function register(
  email: string,
  password: string,
  ipAddress: string,
  userAgent: string
): Promise<RegisterResult> {
  // Check if email exists
  const existingUser = await prisma.user.findUnique({
    where: { email: email.toLowerCase() },
  });

  if (existingUser) {
    throw Object.assign(new Error('Email already registered'), { code: ErrorCode.EMAIL_EXISTS });
  }

  // Validate password strength
  const passwordValidation = validatePasswordRequirements(password);
  if (!passwordValidation.valid) {
    throw Object.assign(new Error(passwordValidation.errors.join(', ')), { code: ErrorCode.WEAK_PASSWORD });
  }

  const strength = checkPasswordStrength(password, [email]);
  if (!strength.isStrong) {
    throw Object.assign(
      new Error(strength.feedback.warning || 'Password is too weak'),
      { code: ErrorCode.WEAK_PASSWORD }
    );
  }

  // Hash password and create user
  const passwordHash = await hashPassword(password);

  const user = await prisma.user.create({
    data: {
      email: email.toLowerCase(),
      passwordHash,
    },
  });

  // Assign default role
  const defaultRole = await prisma.role.findUnique({
    where: { name: 'user' },
  });

  if (defaultRole) {
    await prisma.userRole.create({
      data: {
        userId: user.id,
        roleId: defaultRole.id,
      },
    });
  }

  // Create session and tokens
  const { roles, permissions } = await getUserRolesAndPermissions(user.id);
  const tokenResult = await tokenService.generateTokenPair(
    user.id,
    user.email,
    roles,
    permissions,
    'temp'
  );

  const session = await sessionService.createSession(
    user.id,
    tokenResult.refreshTokenHash,
    ipAddress,
    userAgent
  );

  // Log the registration
  await auditService.logAuthEvent(AuditAction.REGISTER, {
    userId: user.id,
    email: user.email,
    ipAddress,
    userAgent,
  });

  return {
    user: {
      id: user.id,
      email: user.email,
    },
    tokens: {
      accessToken: tokenResult.accessToken,
      refreshToken: tokenResult.refreshToken,
      expiresIn: tokenResult.expiresIn,
    },
  };
}

export async function login(
  email: string,
  password: string,
  ipAddress: string,
  userAgent: string,
  mfaCode?: string,
  deviceFingerprint?: string
): Promise<LoginResult> {
  const normalizedEmail = email.toLowerCase();

  // Check for rate limiting / lockout
  await checkLoginAttempts(normalizedEmail);

  const user = await prisma.user.findUnique({
    where: { email: normalizedEmail },
  });

  if (!user) {
    await recordFailedLogin(normalizedEmail, ipAddress, userAgent);
    throw Object.assign(new Error('Invalid credentials'), { code: ErrorCode.INVALID_CREDENTIALS });
  }

  // Check if account is locked
  if (user.lockedUntil && user.lockedUntil > new Date()) {
    throw Object.assign(
      new Error(`Account is locked. Try again after ${user.lockedUntil.toISOString()}`),
      { code: ErrorCode.ACCOUNT_LOCKED }
    );
  }

  // Verify password
  const isValidPassword = await verifyPassword(user.passwordHash, password);

  if (!isValidPassword) {
    await recordFailedLogin(normalizedEmail, ipAddress, userAgent, user.id);
    await incrementFailedAttempts(user.id);
    throw Object.assign(new Error('Invalid credentials'), { code: ErrorCode.INVALID_CREDENTIALS });
  }

  // Check if MFA is required
  if (user.mfaEnabled) {
    // Check if device is trusted
    const fingerprint = deviceFingerprint || generateDeviceFingerprint(userAgent, ipAddress);
    const isTrusted = await sessionService.isDeviceTrusted(user.id, fingerprint);

    if (!isTrusted) {
      if (!mfaCode) {
        // MFA required but no code provided
        const challenge = await mfaService.createMfaChallenge(user.id);
        return {
          requiresMfa: true,
          mfaChallengeId: challenge.challengeId,
        };
      }

      // Verify MFA code
      const isValidMfa = await mfaService.verifyMfaCode(user.id, mfaCode);

      if (!isValidMfa) {
        // Try backup code
        const isValidBackup = await mfaService.verifyBackupCode(user.id, mfaCode);

        if (!isValidBackup) {
          await auditService.logAuthEvent(AuditAction.LOGIN_FAILURE, {
            userId: user.id,
            email: user.email,
            ipAddress,
            userAgent,
            reason: 'Invalid MFA code',
          });

          throw Object.assign(new Error('Invalid MFA code'), { code: ErrorCode.MFA_INVALID });
        }

        // Log backup code usage
        await auditService.logAuthEvent(AuditAction.MFA_BACKUP_USED, {
          userId: user.id,
          ipAddress,
          userAgent,
        });
      }
    }
  }

  // Clear failed attempts on successful login
  await clearFailedAttempts(user.id);

  // Create session and tokens
  const { roles, permissions } = await getUserRolesAndPermissions(user.id);
  const tokenResult = await tokenService.generateTokenPair(
    user.id,
    user.email,
    roles,
    permissions,
    'temp'
  );

  const fingerprint = deviceFingerprint || generateDeviceFingerprint(userAgent, ipAddress);
  await sessionService.createOrUpdateDevice(user.id, fingerprint, userAgent);

  const session = await sessionService.createSession(
    user.id,
    tokenResult.refreshTokenHash,
    ipAddress,
    userAgent
  );

  // Log successful login
  await auditService.logAuthEvent(AuditAction.LOGIN_SUCCESS, {
    userId: user.id,
    email: user.email,
    ipAddress,
    userAgent,
  });

  return {
    requiresMfa: false,
    user: {
      id: user.id,
      email: user.email,
      emailVerified: user.emailVerified,
      mfaEnabled: user.mfaEnabled,
      roles,
      permissions,
    },
    tokens: {
      accessToken: tokenResult.accessToken,
      refreshToken: tokenResult.refreshToken,
      expiresIn: tokenResult.expiresIn,
    },
  };
}

export async function completeMfaLogin(
  challengeId: string,
  mfaCode: string,
  ipAddress: string,
  userAgent: string
): Promise<{ user: AuthUser; tokens: TokenPair }> {
  const userId = await mfaService.verifyMfaChallenge(challengeId);

  if (!userId) {
    throw Object.assign(new Error('MFA challenge expired'), { code: ErrorCode.TOKEN_EXPIRED });
  }

  const user = await prisma.user.findUnique({
    where: { id: userId },
  });

  if (!user) {
    throw Object.assign(new Error('User not found'), { code: ErrorCode.NOT_FOUND });
  }

  // Verify MFA code
  const isValidMfa = await mfaService.verifyMfaCode(userId, mfaCode);

  if (!isValidMfa) {
    const isValidBackup = await mfaService.verifyBackupCode(userId, mfaCode);

    if (!isValidBackup) {
      throw Object.assign(new Error('Invalid MFA code'), { code: ErrorCode.MFA_INVALID });
    }

    await auditService.logAuthEvent(AuditAction.MFA_BACKUP_USED, {
      userId,
      ipAddress,
      userAgent,
    });
  }

  // Create session and tokens
  const { roles, permissions } = await getUserRolesAndPermissions(userId);
  const tokenResult = await tokenService.generateTokenPair(
    userId,
    user.email,
    roles,
    permissions,
    'temp'
  );

  const fingerprint = generateDeviceFingerprint(userAgent, ipAddress);
  await sessionService.createOrUpdateDevice(userId, fingerprint, userAgent);

  const session = await sessionService.createSession(
    userId,
    tokenResult.refreshTokenHash,
    ipAddress,
    userAgent
  );

  await auditService.logAuthEvent(AuditAction.LOGIN_SUCCESS, {
    userId,
    email: user.email,
    ipAddress,
    userAgent,
    metadata: { mfaVerified: true },
  });

  return {
    user: {
      id: user.id,
      email: user.email,
      emailVerified: user.emailVerified,
      mfaEnabled: user.mfaEnabled,
      roles,
      permissions,
    },
    tokens: {
      accessToken: tokenResult.accessToken,
      refreshToken: tokenResult.refreshToken,
      expiresIn: tokenResult.expiresIn,
    },
  };
}

export async function logout(
  refreshToken: string,
  accessTokenJti: string,
  ipAddress: string,
  userAgent: string
): Promise<void> {
  const refreshTokenHash = hashToken(refreshToken);
  const session = await sessionService.getSessionByRefreshToken(refreshTokenHash);

  if (session) {
    await auditService.logAuthEvent(AuditAction.LOGOUT, {
      userId: session.userId,
      ipAddress,
      userAgent,
    });

    await sessionService.deleteSession(session.id);
  }

  await tokenService.revokeAccessToken(accessTokenJti);
  await tokenService.revokeRefreshToken(refreshToken);
}

export async function logoutAll(
  userId: string,
  ipAddress: string,
  userAgent: string
): Promise<number> {
  const count = await sessionService.deleteAllUserSessions(userId);
  await tokenService.revokeAllUserTokens(userId);

  await auditService.logAuthEvent(AuditAction.LOGOUT_ALL, {
    userId,
    ipAddress,
    userAgent,
    metadata: { sessionsRevoked: count },
  });

  return count;
}

export async function refreshTokens(
  refreshToken: string,
  ipAddress: string,
  userAgent: string
): Promise<TokenPair> {
  const { userId, sessionId } = await tokenService.verifyRefreshToken(refreshToken);

  const user = await prisma.user.findUnique({
    where: { id: userId },
  });

  if (!user) {
    throw Object.assign(new Error('User not found'), { code: ErrorCode.NOT_FOUND });
  }

  const { roles, permissions } = await getUserRolesAndPermissions(userId);

  // Rotate refresh token
  const newRefreshToken = await tokenService.rotateRefreshToken(refreshToken, userId, sessionId);

  // Update session with new refresh token
  await sessionService.updateSessionRefreshToken(sessionId, newRefreshToken.hash);

  // Generate new access token
  const accessToken = await tokenService.generateAccessToken(userId, user.email, roles, permissions);

  return {
    accessToken: accessToken.token,
    refreshToken: newRefreshToken.token,
    expiresIn: accessToken.expiresAt.getTime() - Date.now(),
  };
}

export async function changePassword(
  userId: string,
  currentPassword: string,
  newPassword: string,
  ipAddress: string,
  userAgent: string
): Promise<void> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
  });

  if (!user) {
    throw Object.assign(new Error('User not found'), { code: ErrorCode.NOT_FOUND });
  }

  const isValidPassword = await verifyPassword(user.passwordHash, currentPassword);

  if (!isValidPassword) {
    throw Object.assign(new Error('Current password is incorrect'), { code: ErrorCode.INVALID_CREDENTIALS });
  }

  // Validate new password
  const passwordValidation = validatePasswordRequirements(newPassword);
  if (!passwordValidation.valid) {
    throw Object.assign(new Error(passwordValidation.errors.join(', ')), { code: ErrorCode.WEAK_PASSWORD });
  }

  const strength = checkPasswordStrength(newPassword, [user.email]);
  if (!strength.isStrong) {
    throw Object.assign(
      new Error(strength.feedback.warning || 'Password is too weak'),
      { code: ErrorCode.WEAK_PASSWORD }
    );
  }

  const newPasswordHash = await hashPassword(newPassword);

  await prisma.user.update({
    where: { id: userId },
    data: { passwordHash: newPasswordHash },
  });

  await auditService.logAuthEvent(AuditAction.PASSWORD_CHANGE, {
    userId,
    ipAddress,
    userAgent,
  });
}

export async function requestPasswordReset(
  email: string,
  ipAddress: string,
  userAgent: string
): Promise<string | null> {
  const user = await prisma.user.findUnique({
    where: { email: email.toLowerCase() },
  });

  // Always log the attempt, even if user doesn't exist (for security)
  await auditService.logAuthEvent(AuditAction.PASSWORD_RESET_REQUEST, {
    email,
    userId: user?.id,
    ipAddress,
    userAgent,
  });

  if (!user) {
    // Don't reveal whether email exists
    return null;
  }

  const token = generateSecureToken(32);
  const tokenHash = hashToken(token);

  await prisma.passwordResetToken.create({
    data: {
      userId: user.id,
      token: tokenHash,
      expiresAt: new Date(Date.now() + RedisTTL.passwordReset * 1000),
    },
  });

  return token;
}

export async function resetPassword(
  token: string,
  newPassword: string,
  ipAddress: string,
  userAgent: string
): Promise<void> {
  const tokenHash = hashToken(token);

  const resetToken = await prisma.passwordResetToken.findUnique({
    where: { token: tokenHash },
  });

  if (!resetToken || resetToken.expiresAt < new Date() || resetToken.usedAt) {
    throw Object.assign(new Error('Invalid or expired reset token'), { code: ErrorCode.TOKEN_INVALID });
  }

  const user = await prisma.user.findUnique({
    where: { id: resetToken.userId },
  });

  if (!user) {
    throw Object.assign(new Error('User not found'), { code: ErrorCode.NOT_FOUND });
  }

  // Validate new password
  const passwordValidation = validatePasswordRequirements(newPassword);
  if (!passwordValidation.valid) {
    throw Object.assign(new Error(passwordValidation.errors.join(', ')), { code: ErrorCode.WEAK_PASSWORD });
  }

  const newPasswordHash = await hashPassword(newPassword);

  await prisma.$transaction([
    prisma.user.update({
      where: { id: user.id },
      data: { passwordHash: newPasswordHash },
    }),
    prisma.passwordResetToken.update({
      where: { id: resetToken.id },
      data: { usedAt: new Date() },
    }),
  ]);

  // Revoke all sessions for security
  await sessionService.deleteAllUserSessions(user.id);
  await tokenService.revokeAllUserTokens(user.id);

  await auditService.logAuthEvent(AuditAction.PASSWORD_RESET_COMPLETE, {
    userId: user.id,
    ipAddress,
    userAgent,
  });
}

export async function getUserRolesAndPermissions(userId: string): Promise<{
  roles: string[];
  permissions: string[];
}> {
  const userRoles = await prisma.userRole.findMany({
    where: { userId },
    include: {
      role: {
        include: {
          permissions: true,
        },
      },
    },
  });

  const roles = userRoles.map((ur) => ur.role.name);
  const permissionSet = new Set<string>();

  for (const userRole of userRoles) {
    for (const permission of userRole.role.permissions) {
      permissionSet.add(permission.name);
    }
  }

  return {
    roles,
    permissions: Array.from(permissionSet),
  };
}

// Helper functions for rate limiting

async function checkLoginAttempts(email: string): Promise<void> {
  const redis = getRedisClient();
  const attempts = await redis.get(RedisKeys.loginAttempts(email));

  if (attempts && parseInt(attempts, 10) >= config.security.maxLoginAttempts) {
    throw Object.assign(
      new Error('Too many login attempts. Please try again later.'),
      { code: ErrorCode.RATE_LIMITED }
    );
  }
}

async function recordFailedLogin(
  email: string,
  ipAddress: string,
  userAgent: string,
  userId?: string
): Promise<void> {
  const redis = getRedisClient();

  // Increment attempt counter
  const key = RedisKeys.loginAttempts(email);
  await redis.incr(key);
  await redis.expire(key, RedisTTL.loginAttempts);

  // Log the failed attempt
  await auditService.logAuthEvent(AuditAction.LOGIN_FAILURE, {
    email,
    userId,
    ipAddress,
    userAgent,
  });
}

async function incrementFailedAttempts(userId: string): Promise<void> {
  const user = await prisma.user.update({
    where: { id: userId },
    data: {
      failedAttempts: { increment: 1 },
    },
  });

  // Lock account if too many attempts
  if (user.failedAttempts >= config.security.maxLoginAttempts) {
    const lockoutUntil = new Date(
      Date.now() + config.security.lockoutDurationMinutes * 60 * 1000
    );

    await prisma.user.update({
      where: { id: userId },
      data: { lockedUntil: lockoutUntil },
    });

    await auditService.logAuthEvent(AuditAction.ACCOUNT_LOCKED, {
      userId,
      ipAddress: 'system',
      userAgent: 'system',
      metadata: { lockoutUntil: lockoutUntil.toISOString() },
    });
  }
}

async function clearFailedAttempts(userId: string): Promise<void> {
  await prisma.user.update({
    where: { id: userId },
    data: {
      failedAttempts: 0,
      lockedUntil: null,
    },
  });
}
