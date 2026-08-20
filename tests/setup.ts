import { beforeAll, afterAll } from 'vitest';
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

  // Reset state once per test file. Each file sets up its own users/sessions
  // in its own beforeAll and relies on them persisting across that file's
  // tests, so cleanup belongs here (per file), not in beforeEach.
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

  // Refresh tokens and rate-limit state live in Redis and must also start
  // clean for each file (but persist within it).
  await getRedisClient().flushdb();

  // Mirror the runtime startup steps from src/index.ts so the app under test
  // has what it needs: JWT signing keys and the default roles/permissions.
  await loadJwtKeys();
  await seedDefaultRoles();
});

afterAll(async () => {
  await disconnectDatabase();
  await closeRedis();
});
