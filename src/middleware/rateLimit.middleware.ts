import type { FastifyRequest, FastifyReply } from 'fastify';
import { getRedisClient, RedisKeys } from '../config/redis.js';
import { config } from '../config/index.js';
import { ErrorCode } from '../types/index.js';

interface RateLimitConfig {
  max: number;
  windowMs: number;
  keyPrefix?: string;
  keyGenerator?: (request: FastifyRequest) => string;
  skipSuccessfulRequests?: boolean;
  skipFailedRequests?: boolean;
}

const defaultConfig: RateLimitConfig = {
  max: config.rateLimit.max,
  windowMs: config.rateLimit.windowMs,
};

export function createRateLimiter(options: Partial<RateLimitConfig> = {}) {
  const opts = { ...defaultConfig, ...options };
  const windowSeconds = Math.ceil(opts.windowMs / 1000);

  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    const redis = getRedisClient();

    // Generate key
    let key: string;
    if (opts.keyGenerator) {
      key = opts.keyGenerator(request);
    } else {
      const forwarded = request.headers['x-forwarded-for'];
      const ip = typeof forwarded === 'string'
        ? forwarded.split(',')[0]?.trim() ?? request.ip
        : request.ip;
      key = opts.keyPrefix ? `${opts.keyPrefix}:${ip}` : RedisKeys.rateLimitIp(ip);
    }

    const current = await redis.incr(key);

    if (current === 1) {
      await redis.expire(key, windowSeconds);
    }

    // Set rate limit headers
    const remaining = Math.max(0, opts.max - current);
    const ttl = await redis.ttl(key);

    reply.header('X-RateLimit-Limit', opts.max);
    reply.header('X-RateLimit-Remaining', remaining);
    reply.header('X-RateLimit-Reset', Date.now() + ttl * 1000);

    if (current > opts.max) {
      reply.header('Retry-After', ttl);
      reply.code(429).send({
        success: false,
        error: {
          code: ErrorCode.RATE_LIMITED,
          message: 'Too many requests, please try again later',
          details: {
            retryAfter: ttl,
          },
        },
      });
    }
  };
}

// Rate limiter for authentication endpoints (stricter)
export const authRateLimiter = createRateLimiter({
  max: 5,
  windowMs: 60 * 1000, // 1 minute
  keyPrefix: 'ratelimit:auth',
});

// Rate limiter for login endpoint (even stricter)
export const loginRateLimiter = createRateLimiter({
  max: 5,
  windowMs: 15 * 60 * 1000, // 15 minutes
  keyPrefix: 'ratelimit:login',
});

// Rate limiter for password reset (prevent enumeration)
export const passwordResetRateLimiter = createRateLimiter({
  max: 3,
  windowMs: 60 * 60 * 1000, // 1 hour
  keyPrefix: 'ratelimit:pwreset',
});

// Rate limiter for email verification (prevent abuse)
export const emailVerificationRateLimiter = createRateLimiter({
  max: 3,
  windowMs: 15 * 60 * 1000, // 15 minutes
  keyPrefix: 'ratelimit:emailverify',
});

// Rate limiter per user for sensitive operations
export function userRateLimiter(max: number, windowMs: number) {
  return createRateLimiter({
    max,
    windowMs,
    keyGenerator: (request) => {
      const userId = request.user?.id ?? 'anonymous';
      return RedisKeys.rateLimitUser(userId);
    },
  });
}

// Sliding window rate limiter for more precise control
export async function slidingWindowRateLimit(
  key: string,
  maxRequests: number,
  windowMs: number
): Promise<{ allowed: boolean; remaining: number; resetAt: number }> {
  const redis = getRedisClient();
  const now = Date.now();
  const windowStart = now - windowMs;

  // Remove old entries
  await redis.zremrangebyscore(key, 0, windowStart);

  // Count current entries
  const count = await redis.zcard(key);

  if (count >= maxRequests) {
    const oldestEntry = await redis.zrange(key, 0, 0, 'WITHSCORES');
    const resetAt = oldestEntry[1] ? parseInt(oldestEntry[1], 10) + windowMs : now + windowMs;

    return {
      allowed: false,
      remaining: 0,
      resetAt,
    };
  }

  // Add new entry
  await redis.zadd(key, now, `${now}-${Math.random()}`);
  await redis.pexpire(key, windowMs);

  return {
    allowed: true,
    remaining: maxRequests - count - 1,
    resetAt: now + windowMs,
  };
}

// Exponential backoff for failed attempts
export async function exponentialBackoff(
  key: string,
  baseDelayMs: number = 1000,
  maxDelayMs: number = 300000 // 5 minutes
): Promise<{ blocked: boolean; retryAfterMs: number }> {
  const redis = getRedisClient();

  const attempts = await redis.incr(key);

  if (attempts === 1) {
    await redis.expire(key, Math.ceil(maxDelayMs / 1000));
  }

  if (attempts <= 1) {
    return { blocked: false, retryAfterMs: 0 };
  }

  const delay = Math.min(baseDelayMs * Math.pow(2, attempts - 1), maxDelayMs);
  const lastAttemptKey = `${key}:last`;
  const lastAttemptStr = await redis.get(lastAttemptKey);
  const lastAttempt = lastAttemptStr ? parseInt(lastAttemptStr, 10) : 0;
  const timeSinceLast = Date.now() - lastAttempt;

  if (timeSinceLast < delay) {
    return {
      blocked: true,
      retryAfterMs: delay - timeSinceLast,
    };
  }

  await redis.set(lastAttemptKey, Date.now(), 'EX', Math.ceil(maxDelayMs / 1000));

  return { blocked: false, retryAfterMs: 0 };
}
