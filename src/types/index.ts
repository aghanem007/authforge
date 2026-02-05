import type { FastifyRequest, FastifyReply } from 'fastify';

// User types
export interface AuthUser {
  id: string;
  email: string;
  emailVerified: boolean;
  mfaEnabled: boolean;
  roles: string[];
  permissions: string[];
}

export interface JwtPayload {
  sub: string;
  email: string;
  roles: string[];
  permissions: string[];
  type: 'access' | 'refresh';
  jti: string;
  iat: number;
  exp: number;
  iss: string;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

// Request extensions
export interface AuthenticatedRequest extends FastifyRequest {
  user: AuthUser;
  jti: string;
}

// Session types
export interface SessionInfo {
  id: string;
  ipAddress: string;
  userAgent: string;
  createdAt: Date;
  expiresAt: Date;
  deviceId: string | null;
  isCurrent: boolean;
}

export interface DeviceInfo {
  id: string;
  name: string;
  fingerprint: string;
  trusted: boolean;
  lastUsed: Date;
  createdAt: Date;
}

// MFA types
export interface MfaSetupResult {
  secret: string;
  qrCode: string;
  backupCodes: string[];
}

export interface MfaChallengeResult {
  challengeId: string;
  expiresAt: Date;
}

// Audit types
export enum AuditAction {
  LOGIN_SUCCESS = 'LOGIN_SUCCESS',
  LOGIN_FAILURE = 'LOGIN_FAILURE',
  LOGOUT = 'LOGOUT',
  LOGOUT_ALL = 'LOGOUT_ALL',
  REGISTER = 'REGISTER',
  PASSWORD_CHANGE = 'PASSWORD_CHANGE',
  PASSWORD_RESET_REQUEST = 'PASSWORD_RESET_REQUEST',
  PASSWORD_RESET_COMPLETE = 'PASSWORD_RESET_COMPLETE',
  EMAIL_VERIFICATION = 'EMAIL_VERIFICATION',
  MFA_ENABLED = 'MFA_ENABLED',
  MFA_DISABLED = 'MFA_DISABLED',
  MFA_BACKUP_USED = 'MFA_BACKUP_USED',
  SESSION_REVOKED = 'SESSION_REVOKED',
  DEVICE_TRUSTED = 'DEVICE_TRUSTED',
  DEVICE_UNTRUSTED = 'DEVICE_UNTRUSTED',
  ROLE_ASSIGNED = 'ROLE_ASSIGNED',
  ROLE_REMOVED = 'ROLE_REMOVED',
  ACCOUNT_LOCKED = 'ACCOUNT_LOCKED',
  ACCOUNT_UNLOCKED = 'ACCOUNT_UNLOCKED',
  API_KEY_CREATED = 'API_KEY_CREATED',
  API_KEY_REVOKED = 'API_KEY_REVOKED',
}

export interface AuditLogEntry {
  action: AuditAction;
  userId?: string;
  details: Record<string, unknown>;
  ipAddress: string;
  userAgent: string;
}

// API response types
export interface ApiResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
  };
}

export interface PaginatedResponse<T> {
  items: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

// Error codes
export enum ErrorCode {
  INVALID_CREDENTIALS = 'INVALID_CREDENTIALS',
  ACCOUNT_LOCKED = 'ACCOUNT_LOCKED',
  EMAIL_NOT_VERIFIED = 'EMAIL_NOT_VERIFIED',
  MFA_REQUIRED = 'MFA_REQUIRED',
  MFA_INVALID = 'MFA_INVALID',
  TOKEN_EXPIRED = 'TOKEN_EXPIRED',
  TOKEN_INVALID = 'TOKEN_INVALID',
  UNAUTHORIZED = 'UNAUTHORIZED',
  FORBIDDEN = 'FORBIDDEN',
  NOT_FOUND = 'NOT_FOUND',
  VALIDATION_ERROR = 'VALIDATION_ERROR',
  RATE_LIMITED = 'RATE_LIMITED',
  EMAIL_EXISTS = 'EMAIL_EXISTS',
  WEAK_PASSWORD = 'WEAK_PASSWORD',
  INTERNAL_ERROR = 'INTERNAL_ERROR',
}

// Route handler types
export type RouteHandler<T = unknown> = (
  request: FastifyRequest,
  reply: FastifyReply
) => Promise<ApiResponse<T>>;

export type AuthenticatedRouteHandler<T = unknown> = (
  request: AuthenticatedRequest,
  reply: FastifyReply
) => Promise<ApiResponse<T>>;
