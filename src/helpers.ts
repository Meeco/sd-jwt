import { base64url } from 'jose';

export function generateSalt(length: number): string {
  let salt = '';
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  for (let i = 0; i < length; i++) {
    salt += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return salt;
}

export function base64encode(str: string | Uint8Array): string {
  return base64url.encode(str);
}

export function base64decode(str: string): string {
  return base64url.decode(str).toString();
}
