import { z } from 'zod';

export const emailSchema = z
  .string()
  .email('Invalid email address')
  .max(255, 'Email must not exceed 255 characters')
  .transform((email) => email.toLowerCase().trim());

export const passwordSchema = z
  .string()
  .min(8, 'Password must be at least 8 characters')
  .max(128, 'Password must not exceed 128 characters');

export const registerSchema = z.object({
  email: emailSchema,
  password: passwordSchema,
});

export const loginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1, 'Password is required'),
  mfaCode: z.string().length(6).optional(),
  deviceFingerprint: z.string().optional(),
});

export const refreshTokenSchema = z.object({
  refreshToken: z.string().min(1, 'Refresh token is required'),
});

export const mfaVerifySchema = z.object({
  code: z.string().length(6, 'MFA code must be 6 digits'),
});

export const mfaBackupCodeSchema = z.object({
  code: z.string().regex(/^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/, 'Invalid backup code format'),
});

export const passwordResetRequestSchema = z.object({
  email: emailSchema,
});

export const passwordResetSchema = z.object({
  token: z.string().min(1, 'Reset token is required'),
  password: passwordSchema,
});

export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1, 'Current password is required'),
  newPassword: passwordSchema,
});

export const paginationSchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
});

export const userIdParamSchema = z.object({
  id: z.string().cuid('Invalid user ID'),
});

export const sessionIdParamSchema = z.object({
  id: z.string().cuid('Invalid session ID'),
});

export const deviceIdParamSchema = z.object({
  id: z.string().cuid('Invalid device ID'),
});

export const roleAssignSchema = z.object({
  roleId: z.string().cuid('Invalid role ID'),
});

export const roleCreateSchema = z.object({
  name: z.string().min(1).max(50).regex(/^[a-z_]+$/, 'Role name must be lowercase with underscores only'),
  description: z.string().max(255).optional(),
  permissions: z.array(z.string().cuid()).optional(),
});

export const emailVerificationSchema = z.object({
  token: z.string().min(1, 'Verification token is required'),
});

export const resendVerificationSchema = z.object({
  email: emailSchema,
});

export const auditLogQuerySchema = z.object({
  userId: z.string().cuid().optional(),
  action: z.string().optional(),
  startDate: z.coerce.date().optional(),
  endDate: z.coerce.date().optional(),
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(50),
});

export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type RefreshTokenInput = z.infer<typeof refreshTokenSchema>;
export type MfaVerifyInput = z.infer<typeof mfaVerifySchema>;
export type PasswordResetRequestInput = z.infer<typeof passwordResetRequestSchema>;
export type PasswordResetInput = z.infer<typeof passwordResetSchema>;
export type ChangePasswordInput = z.infer<typeof changePasswordSchema>;
export type PaginationInput = z.infer<typeof paginationSchema>;
export type EmailVerificationInput = z.infer<typeof emailVerificationSchema>;
export type ResendVerificationInput = z.infer<typeof resendVerificationSchema>;
export type AuditLogQueryInput = z.infer<typeof auditLogQuerySchema>;
