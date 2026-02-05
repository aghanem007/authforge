import Redis from 'ioredis';
import { config } from './index.js';

let redisClient: Redis | null = null;

export function getRedisClient(): Redis {
  if (!redisClient) {
    redisClient = new Redis(config.redis.url, {
      maxRetriesPerRequest: 3,
      retryStrategy(times) {
        const delay = Math.min(times * 50, 2000);
        return delay;
      },
      lazyConnect: true,
    });

    redisClient.on('error', (err) => {
      console.error('Redis connection error:', err);
    });

    redisClient.on('connect', () => {
      console.log('Connected to Redis');
    });
  }

  return redisClient;
}

export async function closeRedis(): Promise<void> {
  if (redisClient) {
    await redisClient.quit();
    redisClient = null;
  }
}

// Redis key prefixes
export const RedisKeys = {
  refreshToken: (token: string) => `refresh:${token}`,
  blacklistedToken: (jti: string) => `blacklist:${jti}`,
  userSessions: (userId: string) => `sessions:${userId}`,
  rateLimitIp: (ip: string) => `ratelimit:ip:${ip}`,
  rateLimitUser: (userId: string) => `ratelimit:user:${userId}`,
  loginAttempts: (email: string) => `login:attempts:${email}`,
  mfaChallenge: (userId: string) => `mfa:challenge:${userId}`,
  passwordReset: (token: string) => `pwreset:${token}`,
  emailVerification: (token: string) => `emailverify:${token}`,
  trustedDevice: (userId: string, deviceId: string) => `device:${userId}:${deviceId}`,
} as const;

// TTL values in seconds
export const RedisTTL = {
  accessToken: 15 * 60, // 15 minutes
  refreshToken: 7 * 24 * 60 * 60, // 7 days
  blacklistedToken: 24 * 60 * 60, // 24 hours
  loginAttempts: 15 * 60, // 15 minutes
  mfaChallenge: 5 * 60, // 5 minutes
  passwordReset: 60 * 60, // 1 hour
  emailVerification: 24 * 60 * 60, // 24 hours
  trustedDevice: 30 * 24 * 60 * 60, // 30 days
} as const;
