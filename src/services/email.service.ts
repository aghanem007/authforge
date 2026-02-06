import nodemailer from 'nodemailer';
import type { Transporter } from 'nodemailer';
import { config } from '../config/index.js';

let transporter: Transporter | null = null;

function getTransporter(): Transporter | null {
  if (!config.email.host) {
    return null;
  }

  if (!transporter) {
    transporter = nodemailer.createTransport({
      host: config.email.host,
      port: config.email.port,
      secure: config.email.port === 465,
      auth: config.email.user
        ? {
            user: config.email.user,
            pass: config.email.pass,
          }
        : undefined,
    });
  }

  return transporter;
}

interface EmailOptions {
  to: string;
  subject: string;
  html: string;
  text: string;
}

async function sendEmail(options: EmailOptions): Promise<void> {
  const transport = getTransporter();

  if (!transport) {
    console.log('------- EMAIL (dev mode, no SMTP configured) -------');
    console.log(`To: ${options.to}`);
    console.log(`Subject: ${options.subject}`);
    console.log(`Body:\n${options.text}`);
    console.log('----------------------------------------------------');
    return;
  }

  await transport.sendMail({
    from: config.email.from,
    to: options.to,
    subject: options.subject,
    html: options.html,
    text: options.text,
  });
}

export async function sendVerificationEmail(
  email: string,
  token: string
): Promise<void> {
  const verifyUrl = `${config.app.baseUrl}/auth/verify-email?token=${token}`;

  const html = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #333;">Verify your email address</h2>
      <p>Thanks for signing up for AuthForge. Please verify your email address by clicking the link below:</p>
      <p style="margin: 24px 0;">
        <a href="${verifyUrl}"
           style="background-color: #4f46e5; color: #fff; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
          Verify Email
        </a>
      </p>
      <p style="color: #666; font-size: 14px;">
        Or copy and paste this URL into your browser:<br/>
        <a href="${verifyUrl}" style="color: #4f46e5;">${verifyUrl}</a>
      </p>
      <p style="color: #999; font-size: 12px;">This link expires in 24 hours. If you didn't create an account, you can safely ignore this email.</p>
    </div>
  `;

  const text = [
    'Verify your email address',
    '',
    'Thanks for signing up for AuthForge. Please verify your email address by visiting the link below:',
    '',
    verifyUrl,
    '',
    'This link expires in 24 hours. If you didn\'t create an account, you can safely ignore this email.',
  ].join('\n');

  await sendEmail({
    to: email,
    subject: 'Verify your email address',
    html,
    text,
  });
}

export async function sendPasswordResetEmail(
  email: string,
  token: string
): Promise<void> {
  const resetUrl = `${config.app.baseUrl}/auth/reset-password?token=${token}`;

  const html = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #333;">Reset your password</h2>
      <p>We received a request to reset your password. Click the link below to choose a new one:</p>
      <p style="margin: 24px 0;">
        <a href="${resetUrl}"
           style="background-color: #4f46e5; color: #fff; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
          Reset Password
        </a>
      </p>
      <p style="color: #666; font-size: 14px;">
        Or copy and paste this URL into your browser:<br/>
        <a href="${resetUrl}" style="color: #4f46e5;">${resetUrl}</a>
      </p>
      <p style="color: #999; font-size: 12px;">This link expires in 1 hour. If you didn't request a password reset, you can safely ignore this email.</p>
    </div>
  `;

  const text = [
    'Reset your password',
    '',
    'We received a request to reset your password. Visit the link below to choose a new one:',
    '',
    resetUrl,
    '',
    'This link expires in 1 hour. If you didn\'t request a password reset, you can safely ignore this email.',
  ].join('\n');

  await sendEmail({
    to: email,
    subject: 'Reset your password',
    html,
    text,
  });
}
