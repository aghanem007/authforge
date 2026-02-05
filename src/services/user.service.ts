import { getPrismaClient } from '../config/database.js';
import { hashPassword } from '../utils/password.js';
import * as auditService from './audit.service.js';
import * as sessionService from './session.service.js';
import * as tokenService from './token.service.js';
import { AuditAction, type PaginatedResponse } from '../types/index.js';
import type { User, Role } from '@prisma/client';

const prisma = getPrismaClient();

export interface UserWithRoles extends Omit<User, 'passwordHash' | 'mfaSecret' | 'backupCodes'> {
  roles: { role: Role }[];
}

export async function getUsers(
  page: number,
  limit: number,
  search?: string
): Promise<PaginatedResponse<UserWithRoles>> {
  const where = search
    ? {
        email: {
          contains: search,
          mode: 'insensitive' as const,
        },
      }
    : {};

  const [users, total] = await Promise.all([
    prisma.user.findMany({
      where,
      select: {
        id: true,
        email: true,
        emailVerified: true,
        mfaEnabled: true,
        lockedUntil: true,
        failedAttempts: true,
        createdAt: true,
        updatedAt: true,
        roles: {
          include: {
            role: true,
          },
        },
      },
      orderBy: { createdAt: 'desc' },
      skip: (page - 1) * limit,
      take: limit,
    }),
    prisma.user.count({ where }),
  ]);

  return {
    items: users,
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
    },
  };
}

export async function getUserById(userId: string): Promise<UserWithRoles | null> {
  return prisma.user.findUnique({
    where: { id: userId },
    select: {
      id: true,
      email: true,
      emailVerified: true,
      mfaEnabled: true,
      lockedUntil: true,
      failedAttempts: true,
      createdAt: true,
      updatedAt: true,
      roles: {
        include: {
          role: true,
        },
      },
    },
  });
}

export async function updateUser(
  userId: string,
  data: {
    emailVerified?: boolean;
    lockedUntil?: Date | null;
  },
  adminId: string,
  ipAddress: string,
  userAgent: string
): Promise<UserWithRoles> {
  const user = await prisma.user.update({
    where: { id: userId },
    data,
    select: {
      id: true,
      email: true,
      emailVerified: true,
      mfaEnabled: true,
      lockedUntil: true,
      failedAttempts: true,
      createdAt: true,
      updatedAt: true,
      roles: {
        include: {
          role: true,
        },
      },
    },
  });

  if (data.lockedUntil === null) {
    await auditService.logAuthEvent(AuditAction.ACCOUNT_UNLOCKED, {
      userId,
      ipAddress,
      userAgent,
      metadata: { unlockedBy: adminId },
    });
  }

  return user;
}

export async function deleteUser(
  userId: string,
  adminId: string,
  ipAddress: string,
  userAgent: string
): Promise<void> {
  // Revoke all sessions first
  await sessionService.deleteAllUserSessions(userId);
  await tokenService.revokeAllUserTokens(userId);

  await prisma.user.delete({
    where: { id: userId },
  });

  // Note: Audit log entry will reference deleted user ID
  await auditService.createAuditLog({
    action: 'USER_DELETED' as AuditAction,
    userId: adminId,
    details: { deletedUserId: userId },
    ipAddress,
    userAgent,
  });
}

export async function assignRole(
  userId: string,
  roleId: string,
  adminId: string,
  ipAddress: string,
  userAgent: string
): Promise<void> {
  const role = await prisma.role.findUnique({
    where: { id: roleId },
  });

  if (!role) {
    throw new Error('Role not found');
  }

  await prisma.userRole.upsert({
    where: {
      userId_roleId: { userId, roleId },
    },
    update: {},
    create: {
      userId,
      roleId,
      assignedBy: adminId,
    },
  });

  await auditService.logAuthEvent(AuditAction.ROLE_ASSIGNED, {
    userId,
    ipAddress,
    userAgent,
    metadata: { roleId, roleName: role.name, assignedBy: adminId },
  });
}

export async function removeRole(
  userId: string,
  roleId: string,
  adminId: string,
  ipAddress: string,
  userAgent: string
): Promise<void> {
  const role = await prisma.role.findUnique({
    where: { id: roleId },
  });

  if (!role) {
    throw new Error('Role not found');
  }

  await prisma.userRole.delete({
    where: {
      userId_roleId: { userId, roleId },
    },
  });

  await auditService.logAuthEvent(AuditAction.ROLE_REMOVED, {
    userId,
    ipAddress,
    userAgent,
    metadata: { roleId, roleName: role.name, removedBy: adminId },
  });
}

export async function getRoles(): Promise<Role[]> {
  return prisma.role.findMany({
    include: {
      permissions: true,
    },
    orderBy: { name: 'asc' },
  });
}

export async function createRole(
  name: string,
  description?: string,
  permissionIds?: string[]
): Promise<Role> {
  return prisma.role.create({
    data: {
      name,
      description,
      permissions: permissionIds
        ? {
            connect: permissionIds.map((id) => ({ id })),
          }
        : undefined,
    },
    include: {
      permissions: true,
    },
  });
}

export async function deleteRole(roleId: string): Promise<void> {
  await prisma.role.delete({
    where: { id: roleId },
  });
}

export async function getPermissions() {
  return prisma.permission.findMany({
    orderBy: { name: 'asc' },
  });
}

export async function createPermission(name: string, description?: string) {
  return prisma.permission.create({
    data: { name, description },
  });
}
