import { buildApp } from './app.js';
import { config, validateConfig } from './config/index.js';
import { connectDatabase, disconnectDatabase } from './config/database.js';
import { loadJwtKeys } from './config/jwt.js';
import { getRedisClient, closeRedis } from './config/redis.js';
import { seedDefaultRoles } from './seeds/roles.js';

async function main(): Promise<void> {
  try {
    // Validate environment
    validateConfig();

    console.log('Starting AuthForge...');
    console.log(`Environment: ${config.env}`);

    // Initialize connections
    console.log('Connecting to database...');
    await connectDatabase();

    console.log('Connecting to Redis...');
    const redis = getRedisClient();
    await redis.ping();

    console.log('Loading JWT keys...');
    await loadJwtKeys();

    // Seed default data
    console.log('Seeding default roles...');
    await seedDefaultRoles();

    // Build and start server
    const app = await buildApp();

    await app.listen({
      port: config.port,
      host: '0.0.0.0',
    });

    console.log(`Server running on http://localhost:${config.port}`);
    console.log(`API docs available at http://localhost:${config.port}/docs`);

    // Graceful shutdown
    const shutdown = async (signal: string): Promise<void> => {
      console.log(`\n${signal} received. Shutting down gracefully...`);

      await app.close();
      await disconnectDatabase();
      await closeRedis();

      console.log('Cleanup complete. Exiting.');
      process.exit(0);
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));

  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

main();
