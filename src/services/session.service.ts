import { getPrismaClient } from '../config/database.js';
import { getRedisClient, RedisKeys, RedisTTL } from '../config/redis.js';
import { generateSecureToken, hashToken, generateDeviceFingerprint } from '../utils/crypto.js';
import { parseExpiry } from '../config/jwt.js';
import { config } from '../config/index.js';
import type { SessionInfo, DeviceInfo } from '../types/index.js';
import type { Session, Device } from '@prisma/client';

const prisma = getPrismaClient();

export async function createSession(
  userId: string,
  refreshTokenHash: string,
  ipAddress: string,
  userAgent: string,
  deviceId?: string
): Promise<Session> {
  const expiresInSeconds = parseExpiry(config.jwt.refreshExpiry);
  const expiresAt = new Date(Date.now() + expiresInSeconds * 1000);

  return prisma.session.create({
    data: {
      userId,
      refreshToken: refreshTokenHash,
      deviceId,
      ipAddress,
      userAgent,
      expiresAt,
    },
  });
}

export async function getSessionById(sessionId: string): Promise<Session | null> {
  return prisma.session.findUnique({
    where: { id: sessionId },
  });
}

export async function getSessionByRefreshToken(refreshTokenHash: string): Promise<Session | null> {
  return prisma.session.findUnique({
    where: { refreshToken: refreshTokenHash },
  });
}

export async function getUserSessions(userId: string, currentSessionId?: string): Promise<SessionInfo[]> {
  const sessions = await prisma.session.findMany({
    where: {
      userId,
      expiresAt: { gt: new Date() },
    },
    orderBy: { createdAt: 'desc' },
  });

  return sessions.map((session) => ({
    id: session.id,
    ipAddress: session.ipAddress,
    userAgent: session.userAgent,
    createdAt: session.createdAt,
    expiresAt: session.expiresAt,
    deviceId: session.deviceId,
    isCurrent: session.id === currentSessionId,
  }));
}

export async function deleteSession(sessionId: string): Promise<void> {
  const session = await prisma.session.findUnique({
    where: { id: sessionId },
  });

  if (session) {
    const redis = getRedisClient();
    await redis.del(RedisKeys.refreshToken(session.refreshToken));
    await redis.srem(RedisKeys.userSessions(session.userId), session.refreshToken);
  }

  await prisma.session.delete({
    where: { id: sessionId },
  });
}

export async function deleteAllUserSessions(userId: string): Promise<number> {
  const sessions = await prisma.session.findMany({
    where: { userId },
    select: { refreshToken: true },
  });

  const redis = getRedisClient();
  const pipeline = redis.pipeline();

  for (const session of sessions) {
    pipeline.del(RedisKeys.refreshToken(session.refreshToken));
  }
  pipeline.del(RedisKeys.userSessions(userId));

  await pipeline.exec();

  const result = await prisma.session.deleteMany({
    where: { userId },
  });

  return result.count;
}

export async function cleanExpiredSessions(): Promise<number> {
  const result = await prisma.session.deleteMany({
    where: {
      expiresAt: { lt: new Date() },
    },
  });

  return result.count;
}

export async function updateSessionRefreshToken(
  sessionId: string,
  newRefreshTokenHash: string
): Promise<void> {
  const expiresInSeconds = parseExpiry(config.jwt.refreshExpiry);
  const expiresAt = new Date(Date.now() + expiresInSeconds * 1000);

  await prisma.session.update({
    where: { id: sessionId },
    data: {
      refreshToken: newRefreshTokenHash,
      expiresAt,
    },
  });
}

// Device management

export async function createOrUpdateDevice(
  userId: string,
  fingerprint: string,
  userAgent: string
): Promise<Device> {
  const existingDevice = await prisma.device.findUnique({
    where: {
      userId_fingerprint: { userId, fingerprint },
    },
  });

  if (existingDevice) {
    return prisma.device.update({
      where: { id: existingDevice.id },
      data: { lastUsed: new Date() },
    });
  }

  // Parse user agent for device name
  const deviceName = parseDeviceName(userAgent);

  return prisma.device.create({
    data: {
      userId,
      fingerprint,
      name: deviceName,
    },
  });
}

export async function getUserDevices(userId: string): Promise<DeviceInfo[]> {
  const devices = await prisma.device.findMany({
    where: { userId },
    orderBy: { lastUsed: 'desc' },
  });

  return devices.map((device) => ({
    id: device.id,
    name: device.name,
    fingerprint: device.fingerprint,
    trusted: device.trusted,
    lastUsed: device.lastUsed,
    createdAt: device.createdAt,
  }));
}

export async function trustDevice(deviceId: string, userId: string): Promise<Device> {
  const device = await prisma.device.update({
    where: { id: deviceId, userId },
    data: { trusted: true },
  });

  // Store in Redis for quick lookup
  const redis = getRedisClient();
  await redis.setex(
    RedisKeys.trustedDevice(userId, device.fingerprint),
    RedisTTL.trustedDevice,
    '1'
  );

  return device;
}

export async function untrustDevice(deviceId: string, userId: string): Promise<Device> {
  const device = await prisma.device.update({
    where: { id: deviceId, userId },
    data: { trusted: false },
  });

  const redis = getRedisClient();
  await redis.del(RedisKeys.trustedDevice(userId, device.fingerprint));

  return device;
}

export async function isDeviceTrusted(userId: string, fingerprint: string): Promise<boolean> {
  const redis = getRedisClient();
  const cached = await redis.exists(RedisKeys.trustedDevice(userId, fingerprint));

  if (cached) {
    return true;
  }

  const device = await prisma.device.findUnique({
    where: {
      userId_fingerprint: { userId, fingerprint },
    },
  });

  return device?.trusted ?? false;
}

export async function deleteDevice(deviceId: string, userId: string): Promise<void> {
  const device = await prisma.device.findUnique({
    where: { id: deviceId, userId },
  });

  if (device) {
    const redis = getRedisClient();
    await redis.del(RedisKeys.trustedDevice(userId, device.fingerprint));

    await prisma.device.delete({
      where: { id: deviceId },
    });
  }
}

function parseDeviceName(userAgent: string): string {
  // Simple user agent parsing
  if (userAgent.includes('iPhone')) return 'iPhone';
  if (userAgent.includes('iPad')) return 'iPad';
  if (userAgent.includes('Android')) return 'Android Device';
  if (userAgent.includes('Windows')) return 'Windows PC';
  if (userAgent.includes('Mac')) return 'Mac';
  if (userAgent.includes('Linux')) return 'Linux PC';
  return 'Unknown Device';
}
