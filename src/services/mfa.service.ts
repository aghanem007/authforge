import { authenticator } from 'otplib';
import * as QRCode from 'qrcode';
import { getPrismaClient } from '../config/database.js';
import { getRedisClient, RedisKeys, RedisTTL } from '../config/redis.js';
import { config } from '../config/index.js';
import { generateBackupCodes, hashToken, generateSecureToken, constantTimeCompare } from '../utils/crypto.js';
import { hashPassword, verifyPassword } from '../utils/password.js';
import type { MfaSetupResult, MfaChallengeResult } from '../types/index.js';

const prisma = getPrismaClient();

// Configure TOTP
authenticator.options = {
  step: 30, // 30 second window
  window: 1, // Allow 1 step before/after
};

export async function setupMfa(userId: string): Promise<MfaSetupResult> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { email: true, mfaEnabled: true },
  });

  if (!user) {
    throw new Error('User not found');
  }

  if (user.mfaEnabled) {
    throw new Error('MFA is already enabled');
  }

  // Generate secret
  const secret = authenticator.generateSecret();

  // Generate QR code
  const otpAuthUrl = authenticator.keyuri(user.email, config.mfa.issuer, secret);
  const qrCode = await QRCode.toDataURL(otpAuthUrl);

  // Generate backup codes
  const backupCodes = generateBackupCodes(config.mfa.backupCodesCount);

  // Store secret temporarily (will be saved permanently on verify)
  const redis = getRedisClient();
  await redis.setex(
    `mfa:setup:${userId}`,
    300, // 5 minutes to complete setup
    JSON.stringify({ secret, backupCodes })
  );

  return {
    secret,
    qrCode,
    backupCodes,
  };
}

export async function verifyAndEnableMfa(userId: string, code: string): Promise<boolean> {
  const redis = getRedisClient();
  const setupData = await redis.get(`mfa:setup:${userId}`);

  if (!setupData) {
    throw new Error('MFA setup expired. Please start setup again.');
  }

  const { secret, backupCodes } = JSON.parse(setupData) as {
    secret: string;
    backupCodes: string[];
  };

  // Verify the code
  const isValid = authenticator.verify({ token: code, secret });

  if (!isValid) {
    return false;
  }

  // Hash backup codes for storage
  const hashedBackupCodes = await Promise.all(
    backupCodes.map((code) => hashPassword(code))
  );

  // Save MFA settings to database
  await prisma.user.update({
    where: { id: userId },
    data: {
      mfaEnabled: true,
      mfaSecret: secret,
      backupCodes: hashedBackupCodes,
    },
  });

  // Clean up setup data
  await redis.del(`mfa:setup:${userId}`);

  return true;
}

export async function disableMfa(userId: string, password: string): Promise<void> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { passwordHash: true, mfaEnabled: true },
  });

  if (!user) {
    throw new Error('User not found');
  }

  if (!user.mfaEnabled) {
    throw new Error('MFA is not enabled');
  }

  // Verify password
  const isValidPassword = await verifyPassword(user.passwordHash, password);

  if (!isValidPassword) {
    throw new Error('Invalid password');
  }

  await prisma.user.update({
    where: { id: userId },
    data: {
      mfaEnabled: false,
      mfaSecret: null,
      backupCodes: [],
    },
  });
}

export async function verifyMfaCode(userId: string, code: string): Promise<boolean> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { mfaSecret: true, mfaEnabled: true },
  });

  if (!user || !user.mfaEnabled || !user.mfaSecret) {
    throw new Error('MFA is not enabled');
  }

  return authenticator.verify({ token: code, secret: user.mfaSecret });
}

export async function verifyBackupCode(userId: string, code: string): Promise<boolean> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { backupCodes: true },
  });

  if (!user || user.backupCodes.length === 0) {
    return false;
  }

  // Normalize code (remove dashes, uppercase)
  const normalizedCode = code.toUpperCase().replace(/-/g, '');
  const formattedCode = `${normalizedCode.slice(0, 4)}-${normalizedCode.slice(4, 8)}-${normalizedCode.slice(8, 12)}`;

  // Check each backup code
  for (let i = 0; i < user.backupCodes.length; i++) {
    const hashedCode = user.backupCodes[i];
    if (!hashedCode) continue;

    const isValid = await verifyPassword(hashedCode, formattedCode);

    if (isValid) {
      // Remove the used code
      const updatedCodes = [...user.backupCodes];
      updatedCodes.splice(i, 1);

      await prisma.user.update({
        where: { id: userId },
        data: { backupCodes: updatedCodes },
      });

      return true;
    }
  }

  return false;
}

export async function regenerateBackupCodes(userId: string, password: string): Promise<string[]> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { passwordHash: true, mfaEnabled: true },
  });

  if (!user) {
    throw new Error('User not found');
  }

  if (!user.mfaEnabled) {
    throw new Error('MFA must be enabled to regenerate backup codes');
  }

  const isValidPassword = await verifyPassword(user.passwordHash, password);

  if (!isValidPassword) {
    throw new Error('Invalid password');
  }

  const newBackupCodes = generateBackupCodes(config.mfa.backupCodesCount);

  const hashedBackupCodes = await Promise.all(
    newBackupCodes.map((code) => hashPassword(code))
  );

  await prisma.user.update({
    where: { id: userId },
    data: { backupCodes: hashedBackupCodes },
  });

  return newBackupCodes;
}

export async function getBackupCodesCount(userId: string): Promise<number> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { backupCodes: true },
  });

  return user?.backupCodes.length ?? 0;
}

// MFA challenge for login flow
export async function createMfaChallenge(userId: string): Promise<MfaChallengeResult> {
  const challengeId = generateSecureToken(16);
  const expiresAt = new Date(Date.now() + RedisTTL.mfaChallenge * 1000);

  const redis = getRedisClient();
  await redis.setex(
    RedisKeys.mfaChallenge(challengeId),
    RedisTTL.mfaChallenge,
    userId
  );

  return { challengeId, expiresAt };
}

export async function verifyMfaChallenge(challengeId: string): Promise<string | null> {
  const redis = getRedisClient();
  const userId = await redis.get(RedisKeys.mfaChallenge(challengeId));

  if (userId) {
    await redis.del(RedisKeys.mfaChallenge(challengeId));
  }

  return userId;
}
