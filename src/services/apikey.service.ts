import { getPrismaClient } from '../config/database.js';
import { generateApiKey, hashToken } from '../utils/crypto.js';
import type { ApiKey } from '@prisma/client';

const prisma = getPrismaClient();

export interface ApiKeyInfo {
  id: string;
  name: string;
  keyPrefix: string;
  permissions: string[];
  lastUsedAt: Date | null;
  expiresAt: Date | null;
  revokedAt: Date | null;
  createdAt: Date;
}

export async function createApiKey(
  userId: string,
  name: string,
  permissions: string[],
  expiresAt?: Date
): Promise<{ apiKey: ApiKeyInfo; rawKey: string }> {
  const { key, prefix, hash } = generateApiKey();

  const created = await prisma.apiKey.create({
    data: {
      userId,
      name,
      keyHash: hash,
      keyPrefix: prefix,
      permissions,
      expiresAt: expiresAt ?? null,
    },
  });

  return {
    apiKey: toApiKeyInfo(created),
    rawKey: key,
  };
}

export async function listApiKeys(userId: string): Promise<ApiKeyInfo[]> {
  const keys = await prisma.apiKey.findMany({
    where: { userId },
    orderBy: { createdAt: 'desc' },
  });

  return keys.map(toApiKeyInfo);
}

export async function getApiKeyById(id: string, userId: string): Promise<ApiKeyInfo | null> {
  const key = await prisma.apiKey.findFirst({
    where: { id, userId },
  });

  return key ? toApiKeyInfo(key) : null;
}

export async function revokeApiKey(id: string, userId: string): Promise<ApiKeyInfo | null> {
  const key = await prisma.apiKey.findFirst({
    where: { id, userId },
  });

  if (!key) return null;
  if (key.revokedAt) return toApiKeyInfo(key);

  const updated = await prisma.apiKey.update({
    where: { id },
    data: { revokedAt: new Date() },
  });

  return toApiKeyInfo(updated);
}

export async function deleteApiKey(id: string, userId: string): Promise<boolean> {
  const key = await prisma.apiKey.findFirst({
    where: { id, userId },
  });

  if (!key) return false;

  await prisma.apiKey.delete({ where: { id } });
  return true;
}

export async function validateApiKey(rawKey: string): Promise<{ userId: string; permissions: string[] } | null> {
  const hash = hashToken(rawKey);

  const key = await prisma.apiKey.findUnique({
    where: { keyHash: hash },
  });

  if (!key) return null;
  if (key.revokedAt) return null;
  if (key.expiresAt && key.expiresAt < new Date()) return null;

  // Update last used timestamp
  await prisma.apiKey.update({
    where: { id: key.id },
    data: { lastUsedAt: new Date() },
  });

  return {
    userId: key.userId,
    permissions: key.permissions,
  };
}

function toApiKeyInfo(key: ApiKey): ApiKeyInfo {
  return {
    id: key.id,
    name: key.name,
    keyPrefix: key.keyPrefix,
    permissions: key.permissions,
    lastUsedAt: key.lastUsedAt,
    expiresAt: key.expiresAt,
    revokedAt: key.revokedAt,
    createdAt: key.createdAt,
  };
}
