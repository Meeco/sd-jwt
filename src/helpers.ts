export function generateSalt(length: number): string {
  let salt = '';
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  for (let i = 0; i < length; i++) {
    salt += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return salt;
}

export function base64encode(input: string | Uint8Array): string {
  return Buffer.from(input).toString('base64url');
}

export function base64decode(input: string): string {
  return Buffer.from(input, 'base64url').toString();
}
