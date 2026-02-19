import { getPrismaClient } from '../config/database.js';
import type { AuditAction, AuditLogEntry, PaginatedResponse } from '../types/index.js';
import type { AuditLog, Prisma } from '@prisma/client';

const prisma = getPrismaClient();

export async function createAuditLog(entry: AuditLogEntry): Promise<AuditLog> {
  return prisma.auditLog.create({
    data: {
      ...(entry.userId ? { userId: entry.userId } : {}),
      action: entry.action,
      details: entry.details as unknown as Prisma.InputJsonValue,
      ipAddress: entry.ipAddress,
      userAgent: entry.userAgent,
    },
  });
}

export async function logAuthEvent(
  action: AuditAction,
  options: {
    userId?: string;
    email?: string;
    ipAddress: string;
    userAgent: string;
    success?: boolean;
    reason?: string;
    metadata?: Record<string, unknown>;
  }
): Promise<void> {
  const details: Record<string, unknown> = {};

  if (options.email) {
    details['email'] = options.email;
  }
  if (options.success !== undefined) {
    details['success'] = options.success;
  }
  if (options.reason) {
    details['reason'] = options.reason;
  }
  if (options.metadata) {
    Object.assign(details, options.metadata);
  }

  await createAuditLog({
    action,
    ...(options.userId ? { userId: options.userId } : {}),
    details,
    ipAddress: options.ipAddress,
    userAgent: options.userAgent,
  });
}

export async function getAuditLogs(options: {
  userId?: string | undefined;
  action?: string | undefined;
  startDate?: Date | undefined;
  endDate?: Date | undefined;
  page: number;
  limit: number;
}): Promise<PaginatedResponse<AuditLog>> {
  const where: Record<string, unknown> = {};

  if (options.userId) {
    where['userId'] = options.userId;
  }
  if (options.action) {
    where['action'] = options.action;
  }
  if (options.startDate || options.endDate) {
    where['createdAt'] = {};
    if (options.startDate) {
      (where['createdAt'] as Record<string, Date>)['gte'] = options.startDate;
    }
    if (options.endDate) {
      (where['createdAt'] as Record<string, Date>)['lte'] = options.endDate;
    }
  }

  const [items, total] = await Promise.all([
    prisma.auditLog.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      skip: (options.page - 1) * options.limit,
      take: options.limit,
      include: {
        user: {
          select: { id: true, email: true },
        },
      },
    }),
    prisma.auditLog.count({ where }),
  ]);

  return {
    items,
    pagination: {
      page: options.page,
      limit: options.limit,
      total,
      totalPages: Math.ceil(total / options.limit),
    },
  };
}

export async function getUserActivityLogs(
  userId: string,
  page: number,
  limit: number
): Promise<PaginatedResponse<AuditLog>> {
  return getAuditLogs({ userId, page, limit });
}

export async function exportAuditLogs(options: {
  userId?: string | undefined;
  action?: string | undefined;
  startDate?: Date | undefined;
  endDate?: Date | undefined;
}): Promise<AuditLog[]> {
  const where: Record<string, unknown> = {};

  if (options.userId) {
    where['userId'] = options.userId;
  }
  if (options.action) {
    where['action'] = options.action;
  }
  if (options.startDate || options.endDate) {
    where['createdAt'] = {};
    if (options.startDate) {
      (where['createdAt'] as Record<string, Date>)['gte'] = options.startDate;
    }
    if (options.endDate) {
      (where['createdAt'] as Record<string, Date>)['lte'] = options.endDate;
    }
  }

  return prisma.auditLog.findMany({
    where,
    orderBy: { createdAt: 'desc' },
    include: {
      user: {
        select: { id: true, email: true },
      },
    },
  });
}

export async function getSecurityAlerts(userId: string, days: number = 7): Promise<AuditLog[]> {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);

  const suspiciousActions = [
    'LOGIN_FAILURE',
    'ACCOUNT_LOCKED',
    'PASSWORD_RESET_REQUEST',
    'MFA_DISABLED',
    'SESSION_REVOKED',
    'LOGOUT_ALL',
  ];

  return prisma.auditLog.findMany({
    where: {
      userId,
      action: { in: suspiciousActions },
      createdAt: { gte: startDate },
    },
    orderBy: { createdAt: 'desc' },
    take: 50,
  });
}
