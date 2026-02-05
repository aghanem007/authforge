import * as fs from 'fs';
import * as path from 'path';
import { generateKeyPair, exportSPKI, exportPKCS8 } from 'jose';
import { config } from './index.js';

let privateKey: string | null = null;
let publicKey: string | null = null;

export async function loadJwtKeys(): Promise<{ privateKey: string; publicKey: string }> {
  if (privateKey && publicKey) {
    return { privateKey, publicKey };
  }

  const privateKeyPath = path.resolve(config.jwt.privateKeyPath);
  const publicKeyPath = path.resolve(config.jwt.publicKeyPath);

  try {
    privateKey = fs.readFileSync(privateKeyPath, 'utf-8');
    publicKey = fs.readFileSync(publicKeyPath, 'utf-8');
    console.log('JWT keys loaded from files');
  } catch {
    console.log('JWT key files not found, generating new keys...');
    const keys = await generateJwtKeys();
    privateKey = keys.privateKey;
    publicKey = keys.publicKey;

    // Ensure directory exists
    const keysDir = path.dirname(privateKeyPath);
    if (!fs.existsSync(keysDir)) {
      fs.mkdirSync(keysDir, { recursive: true });
    }

    fs.writeFileSync(privateKeyPath, privateKey, { mode: 0o600 });
    fs.writeFileSync(publicKeyPath, publicKey, { mode: 0o644 });
    console.log('JWT keys generated and saved');
  }

  return { privateKey, publicKey };
}

export async function generateJwtKeys(): Promise<{ privateKey: string; publicKey: string }> {
  const { publicKey: pubKey, privateKey: privKey } = await generateKeyPair('RS256', {
    modulusLength: 2048,
  });

  const privateKeyPem = await exportPKCS8(privKey);
  const publicKeyPem = await exportSPKI(pubKey);

  return {
    privateKey: privateKeyPem,
    publicKey: publicKeyPem,
  };
}

export function getPrivateKey(): string {
  if (!privateKey) {
    throw new Error('JWT keys not loaded. Call loadJwtKeys() first.');
  }
  return privateKey;
}

export function getPublicKey(): string {
  if (!publicKey) {
    throw new Error('JWT keys not loaded. Call loadJwtKeys() first.');
  }
  return publicKey;
}

export function parseExpiry(expiry: string): number {
  const match = expiry.match(/^(\d+)([smhd])$/);
  if (!match) {
    throw new Error(`Invalid expiry format: ${expiry}`);
  }

  const value = parseInt(match[1] as string, 10);
  const unit = match[2];

  switch (unit) {
    case 's':
      return value;
    case 'm':
      return value * 60;
    case 'h':
      return value * 60 * 60;
    case 'd':
      return value * 60 * 60 * 24;
    default:
      throw new Error(`Invalid expiry unit: ${unit}`);
  }
}
