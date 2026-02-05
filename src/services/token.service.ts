import { SignJWT, jwtVerify, importPKCS8, importSPKI, type KeyLike } from 'jose';
import { config } from '../config/index.js';
import { getPrivateKey, getPublicKey, parseExpiry } from '../config/jwt.js';
import { getRedisClient, RedisKeys, RedisTTL } from '../config/redis.js';
import { generateUuid, generateSecureToken, hashToken } from '../utils/crypto.js';
import type { JwtPayload, TokenPair } from '../types/index.js';

let privateKey: KeyLike | null = null;
let publicKey: KeyLike | null = null;

async function getKeys(): Promise<{ privateKey: KeyLike; publicKey: KeyLike }> {
  if (!privateKey || !publicKey) {
    const privateKeyPem = getPrivateKey();
    const publicKeyPem = getPublicKey();

    privateKey = await importPKCS8(privateKeyPem, 'RS256');
    publicKey = await importSPKI(publicKeyPem, 'RS256');
  }

  return { privateKey, publicKey };
}

export async function generateAccessToken(
  userId: string,
  email: string,
  roles: string[],
  permissions: string[]
): Promise<{ token: string; jti: string; expiresAt: Date }> {
  const { privateKey: key } = await getKeys();
  const jti = generateUuid();
  const expiresInSeconds = parseExpiry(config.jwt.accessExpiry);
  const expiresAt = new Date(Date.now() + expiresInSeconds * 1000);

  const token = await new SignJWT({
    email,
    roles,
    permissions,
    type: 'access',
  })
    .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
    .setSubject(userId)
    .setIssuedAt()
    .setExpirationTime(expiresAt)
    .setIssuer(config.jwt.issuer)
    .setJti(jti)
    .sign(key);

  return { token, jti, expiresAt };
}

export async function generateRefreshToken(
  userId: string,
  sessionId: string
): Promise<{ token: string; hash: string; expiresAt: Date }> {
  const token = generateSecureToken(48);
  const hash = hashToken(token);
  const expiresInSeconds = parseExpiry(config.jwt.refreshExpiry);
  const expiresAt = new Date(Date.now() + expiresInSeconds * 1000);

  const redis = getRedisClient();

  // Store refresh token in Redis
  await redis.setex(
    RedisKeys.refreshToken(hash),
    expiresInSeconds,
    JSON.stringify({ userId, sessionId, createdAt: Date.now() })
  );

  // Add to user's sessions set
  await redis.sadd(RedisKeys.userSessions(userId), hash);

  return { token, hash, expiresAt };
}

export async function generateTokenPair(
  userId: string,
  email: string,
  roles: string[],
  permissions: string[],
  sessionId: string
): Promise<TokenPair & { refreshTokenHash: string }> {
  const [accessResult, refreshResult] = await Promise.all([
    generateAccessToken(userId, email, roles, permissions),
    generateRefreshToken(userId, sessionId),
  ]);

  return {
    accessToken: accessResult.token,
    refreshToken: refreshResult.token,
    refreshTokenHash: refreshResult.hash,
    expiresIn: parseExpiry(config.jwt.accessExpiry),
  };
}

export async function verifyAccessToken(token: string): Promise<JwtPayload> {
  const { publicKey: key } = await getKeys();

  const { payload } = await jwtVerify(token, key, {
    issuer: config.jwt.issuer,
  });

  // Check if token is blacklisted
  const redis = getRedisClient();
  const isBlacklisted = await redis.exists(RedisKeys.blacklistedToken(payload.jti as string));

  if (isBlacklisted) {
    throw new Error('Token has been revoked');
  }

  return payload as unknown as JwtPayload;
}

export async function verifyRefreshToken(token: string): Promise<{ userId: string; sessionId: string }> {
  const hash = hashToken(token);
  const redis = getRedisClient();

  const data = await redis.get(RedisKeys.refreshToken(hash));

  if (!data) {
    throw new Error('Invalid or expired refresh token');
  }

  const parsed = JSON.parse(data) as { userId: string; sessionId: string };
  return parsed;
}

export async function revokeAccessToken(jti: string): Promise<void> {
  const redis = getRedisClient();
  await redis.setex(RedisKeys.blacklistedToken(jti), RedisTTL.blacklistedToken, '1');
}

export async function revokeRefreshToken(token: string): Promise<void> {
  const hash = hashToken(token);
  const redis = getRedisClient();

  const data = await redis.get(RedisKeys.refreshToken(hash));

  if (data) {
    const { userId } = JSON.parse(data) as { userId: string };
    await redis.srem(RedisKeys.userSessions(userId), hash);
  }

  await redis.del(RedisKeys.refreshToken(hash));
}

export async function revokeAllUserTokens(userId: string): Promise<number> {
  const redis = getRedisClient();

  // Get all refresh tokens for user
  const tokens = await redis.smembers(RedisKeys.userSessions(userId));

  if (tokens.length === 0) {
    return 0;
  }

  // Delete all refresh tokens
  const pipeline = redis.pipeline();
  for (const tokenHash of tokens) {
    pipeline.del(RedisKeys.refreshToken(tokenHash));
  }
  pipeline.del(RedisKeys.userSessions(userId));

  await pipeline.exec();

  return tokens.length;
}

export async function rotateRefreshToken(
  oldToken: string,
  userId: string,
  sessionId: string
): Promise<{ token: string; hash: string; expiresAt: Date }> {
  // Revoke old token and generate new one
  await revokeRefreshToken(oldToken);
  return generateRefreshToken(userId, sessionId);
}
