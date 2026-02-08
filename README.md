# AuthForge

A production-grade authentication and security service built with Node.js, TypeScript, and Fastify.

## Features

- **User Authentication** - Registration, login, logout with JWT tokens
- **Multi-Factor Authentication** - TOTP-based 2FA with backup codes
- **Session Management** - Track and manage user sessions across devices
- **Role-Based Access Control** - Granular permissions system
- **Security Hardening** - Rate limiting, brute force protection, account lockout
- **Audit Logging** - Comprehensive logging of all security events
- **Device Management** - Trust and manage known devices

## Tech Stack

- **Runtime**: Node.js + TypeScript
- **Framework**: Fastify
- **Database**: PostgreSQL
- **Cache**: Redis
- **ORM**: Prisma
- **Password Hashing**: Argon2
- **Tokens**: JWT with RS256

## Quick Start

### Prerequisites

- Node.js 20+
- Docker and Docker Compose
- pnpm (recommended) or npm

### Setup

1. Clone the repository:
```bash
git clone https://github.com/aghanem007/authforge.git
cd authforge
```

2. Install dependencies:
```bash
npm install
```

3. Copy environment file:
```bash
cp .env.example .env
```

4. Start the services:
```bash
docker-compose up -d postgres redis
```

5. Generate JWT keys:
```bash
npm run keys:generate
```

6. Run database migrations:
```bash
npm run prisma:migrate
```

7. Start the development server:
```bash
npm run dev
```

The API will be available at `http://localhost:3000`. API documentation is at `http://localhost:3000/docs`.

## API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/register` | Create a new account |
| POST | `/auth/login` | Login and get tokens |
| POST | `/auth/refresh` | Refresh access token |
| POST | `/auth/logout` | Logout current session |
| POST | `/auth/logout-all` | Logout all sessions |
| POST | `/auth/forgot-password` | Request password reset |
| POST | `/auth/reset-password` | Reset password |
| GET | `/auth/me` | Get current user |

### MFA
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/mfa/setup` | Start MFA setup |
| POST | `/mfa/verify` | Verify and enable MFA |
| POST | `/mfa/disable` | Disable MFA |
| GET | `/mfa/backup-codes` | Get backup codes count |
| POST | `/mfa/regenerate-codes` | Generate new backup codes |

### Sessions
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/sessions` | List active sessions |
| DELETE | `/sessions/:id` | Revoke a session |
| GET | `/sessions/devices` | List known devices |
| POST | `/sessions/devices/:id/trust` | Trust a device |

### API Keys
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api-keys` | Create a new API key |
| GET | `/api-keys` | List your API keys |
| GET | `/api-keys/:id` | Get API key details |
| POST | `/api-keys/:id/revoke` | Revoke an API key |
| DELETE | `/api-keys/:id` | Delete an API key |

### Admin
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/admin/users` | List all users |
| GET | `/admin/users/:id` | Get user details |
| PATCH | `/admin/users/:id` | Update user |
| DELETE | `/admin/users/:id` | Delete user |
| POST | `/admin/users/:id/roles` | Assign role |
| GET | `/admin/audit/logs` | Query audit logs |

## Development

### Running Tests
```bash
npm test
```

### Database Management
```bash
# Create a migration
npm run prisma:migrate

# Open Prisma Studio
npm run prisma:studio

# Generate Prisma client
npm run prisma:generate
```

### Docker

Build and run with Docker Compose:
```bash
docker-compose up --build
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NODE_ENV` | Environment | development |
| `PORT` | Server port | 3000 |
| `DATABASE_URL` | PostgreSQL connection string | - |
| `REDIS_URL` | Redis connection string | - |
| `JWT_ACCESS_EXPIRY` | Access token expiry | 15m |
| `JWT_REFRESH_EXPIRY` | Refresh token expiry | 7d |
| `MAX_LOGIN_ATTEMPTS` | Failed attempts before lockout | 5 |
| `LOCKOUT_DURATION_MINUTES` | Account lockout duration | 15 |

## Security

- Passwords are hashed using Argon2id
- JWTs are signed with RS256 (asymmetric keys)
- Rate limiting on sensitive endpoints
- Brute force protection with exponential backoff
- Account lockout after repeated failures
- All security events are logged

## Status

This project is under active development. Core authentication features are functional.

### What's Working
- User registration, login, logout
- JWT token refresh flow
- Password reset (token generation + email delivery)
- Email verification flow
- MFA setup and verification
- Session management
- Role-based access control
- API key management (create, list, revoke, delete)
- Audit logging
- Rate limiting

### Roadmap
- [ ] API key rotation and key-based authentication
- [ ] Expanded test coverage (sessions, admin, audit, API keys)
- [ ] Account recovery options
