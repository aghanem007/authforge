import Fastify, { type FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import cookie from '@fastify/cookie';
import rateLimit from '@fastify/rate-limit';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';

import { config } from './config/index.js';
import { getRedisClient } from './config/redis.js';
import { errorHandler, notFoundHandler } from './middleware/error.middleware.js';

import { authRoutes } from './routes/auth.routes.js';
import { mfaRoutes } from './routes/mfa.routes.js';
import { sessionRoutes } from './routes/session.routes.js';
import { adminRoutes } from './routes/admin.routes.js';
import { auditRoutes } from './routes/audit.routes.js';
import { apiKeyRoutes } from './routes/apikey.routes.js';

export async function buildApp() {
  const loggerConfig = config.env === 'development'
    ? {
        level: 'info' as const,
        transport: {
          target: 'pino-pretty',
          options: {
            colorize: true,
          },
        },
      }
    : {
        level: 'warn' as const,
      };

  const app = Fastify({
    logger: loggerConfig,
    trustProxy: true,
  });

  // Security plugins
  await app.register(helmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'blob:'],
        scriptSrc: ["'self'"],
      },
    },
  });

  await app.register(cors, {
    origin: config.env === 'development' ? true : false,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  });

  await app.register(cookie);

  // Rate limiting
  const redis = getRedisClient();
  await app.register(rateLimit, {
    max: config.rateLimit.max,
    timeWindow: config.rateLimit.windowMs,
    redis,
  });

  // API Documentation
  await app.register(swagger, {
    openapi: {
      info: {
        title: 'AuthForge API',
        description: 'Security-first authentication backend',
        version: '1.0.0',
      },
      servers: [
        {
          url: `http://localhost:${config.port}`,
          description: 'Development server',
        },
      ],
      components: {
        securitySchemes: {
          bearerAuth: {
            type: 'http',
            scheme: 'bearer',
            bearerFormat: 'JWT',
          },
        },
      },
    },
  });

  await app.register(swaggerUi, {
    routePrefix: '/docs',
    uiConfig: {
      docExpansion: 'list',
      deepLinking: false,
    },
  });

  // Health check
  app.get('/health', async () => {
    return {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      version: '1.0.0',
    };
  });

  // API routes
  await app.register(authRoutes, { prefix: '/auth' });
  await app.register(mfaRoutes, { prefix: '/mfa' });
  await app.register(sessionRoutes, { prefix: '/sessions' });
  await app.register(adminRoutes, { prefix: '/admin' });
  await app.register(auditRoutes, { prefix: '/audit' });
  await app.register(apiKeyRoutes, { prefix: '/api-keys' });

  // Error handling
  app.setErrorHandler((error, request, reply) => {
    errorHandler(error, request, reply);
  });
  app.setNotFoundHandler((request, reply) => {
    notFoundHandler(request, reply);
  });

  return app;
}
