import * as fs from 'fs';
import * as path from 'path';
import { generateJwtKeys } from '../src/config/jwt.js';

async function main(): Promise<void> {
  console.log('Generating RSA key pair for JWT signing...\n');

  const { privateKey, publicKey } = await generateJwtKeys();

  const keysDir = path.join(process.cwd(), 'keys');

  if (!fs.existsSync(keysDir)) {
    fs.mkdirSync(keysDir, { recursive: true });
  }

  const privateKeyPath = path.join(keysDir, 'private.pem');
  const publicKeyPath = path.join(keysDir, 'public.pem');

  fs.writeFileSync(privateKeyPath, privateKey, { mode: 0o600 });
  fs.writeFileSync(publicKeyPath, publicKey, { mode: 0o644 });

  console.log('Keys generated successfully!');
  console.log(`Private key: ${privateKeyPath}`);
  console.log(`Public key: ${publicKeyPath}`);
  console.log('\nIMPORTANT: Keep your private key secure and never commit it to version control!');
}

main().catch(console.error);
