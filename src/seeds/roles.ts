import { getPrismaClient } from '../config/database.js';

const prisma = getPrismaClient();

const defaultPermissions = [
  { name: 'users:read', description: 'View user information' },
  { name: 'users:write', description: 'Create and update users' },
  { name: 'users:delete', description: 'Delete users' },
  { name: 'roles:read', description: 'View roles' },
  { name: 'roles:write', description: 'Create and update roles' },
  { name: 'roles:delete', description: 'Delete roles' },
  { name: 'audit:read', description: 'View audit logs' },
  { name: 'audit:export', description: 'Export audit logs' },
  { name: 'sessions:manage', description: 'Manage all user sessions' },
];

const defaultRoles = [
  {
    name: 'user',
    description: 'Standard user role',
    permissions: [] as string[],
  },
  {
    name: 'moderator',
    description: 'Moderator with limited admin access',
    permissions: ['users:read', 'audit:read'],
  },
  {
    name: 'admin',
    description: 'Full administrative access',
    permissions: defaultPermissions.map((p) => p.name),
  },
];

export async function seedDefaultRoles(): Promise<void> {
  // Create permissions
  for (const permission of defaultPermissions) {
    await prisma.permission.upsert({
      where: { name: permission.name },
      update: {},
      create: permission,
    });
  }

  // Create roles with permissions
  for (const role of defaultRoles) {
    const existingRole = await prisma.role.findUnique({
      where: { name: role.name },
    });

    if (!existingRole) {
      await prisma.role.create({
        data: {
          name: role.name,
          description: role.description,
          permissions: {
            connect: role.permissions.map((name) => ({ name })),
          },
        },
      });
      console.log(`Created role: ${role.name}`);
    }
  }
}
