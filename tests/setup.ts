import { beforeAll, afterAll, beforeEach } from 'vitest';
import { getPrismaClient, disconnectDatabase } from '../src/config/database.js';
import { closeRedis, getRedisClient } from '../src/config/redis.js';
import { loadJwtKeys } from '../src/config/jwt.js';
import { seedDefaultRoles } from '../src/seeds/roles.js';

const prisma = getPrismaClient();

beforeAll(async () => {
  // Ensure test database is used
  if (!process.env['DATABASE_URL']?.includes('test')) {
    throw new Error('Tests must be run against a test database');
  }

  // Mirror the runtime startup steps from src/index.ts so the app under test
  // has what it needs: JWT signing keys and the default roles/permissions.
  await loadJwtKeys();
  await seedDefaultRoles();
});

beforeEach(async () => {
  // Clean up database before each test
  const tables = [
    'AuditLog',
    'Device',
    'Session',
    'UserRole',
    'PasswordResetToken',
    'EmailVerificationToken',
    'ApiKey',
    'User',
  ];

  for (const table of tables) {
    await prisma.$executeRawUnsafe(`TRUNCATE TABLE "${table}" CASCADE`);
  }

  // Clear Redis
  const redis = getRedisClient();
  await redis.flushdb();
});

afterAll(async () => {
  await disconnectDatabase();
  await closeRedis();
});
