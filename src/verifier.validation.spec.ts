import crypto from 'crypto';
import { exportJWK, generateKeyPair, importJWK, jwtVerify, SignJWT } from 'jose';
import { base64encode, decodeJWT } from './helpers';
import { issueSDJWT } from './issuer';
import { ISSUER_KEYPAIR } from './test-utils/params';
import { JWK, KeyBindingVerifier } from './types';
import { verifySDJWT } from './verifier';

const AUDIENCE = 'https://verifier.example.com';
const NONCE = 'n-0S6_WzA2Mj';

const hasher = (data: string): string => base64encode(crypto.createHash('sha256').update(data).digest());

const getHasher = () => Promise.resolve(hasher);

const signer = async (header, payload) => {
  const issuerPrivateKey = await importJWK(ISSUER_KEYPAIR.PRIVATE_KEY_JWK, header.alg);
  return (await new SignJWT(payload).setProtectedHeader(header).sign(issuerPrivateKey)).split('.').pop();
};

const verifier = async (jwt: string) => {
  const issuerPublicKey = await importJWK(ISSUER_KEYPAIR.PUBLIC_KEY_JWK, 'ES256');
  return !!(await jwtVerify(jwt, issuerPublicKey));
};

const kbVerifier: KeyBindingVerifier = async (kbjwt, holderJWK) => {
  const { header, payload } = decodeJWT(kbjwt);

  if (payload.aud !== AUDIENCE) throw new Error('aud mismatch');
  if (payload.nonce !== NONCE) throw new Error('nonce mismatch');

  const holderKey = await importJWK(holderJWK as any, header.alg);
  return !!(await jwtVerify(kbjwt, holderKey));
};

describe('verifySDJWT', () => {
  let holderPrivateKey: any;
  let holderPublicJWK: JWK;

  const issue = () =>
    issueSDJWT(
      { alg: 'ES256' },
      { iss: 'https://issuer.example.com', sub: 'subject-id', given_name: 'Max', is_over_18: true },
      { _sd: ['given_name', 'is_over_18'] },
      { hash: { alg: 'sha-256', callback: hasher }, signer, cnf: { jwk: holderPublicJWK } },
    );

  const signKBJWT = async (presentation: string, typ = 'kb+jwt') =>
    new SignJWT({
      aud: AUDIENCE,
      nonce: NONCE,
      iat: Math.floor(Date.now() / 1000),
      sd_hash: hasher(presentation),
    })
      .setProtectedHeader({ alg: 'ES256', typ })
      .sign(holderPrivateKey);

  beforeAll(async () => {
    const { privateKey, publicKey } = await generateKeyPair('ES256');
    holderPrivateKey = privateKey;
    holderPublicJWK = (await exportJWK(publicKey)) as JWK;
  });

  it('accepts a presentation whose KB-JWT was signed over exactly what is presented', async () => {
    const presentation = await issue(); // '<jwt>~<d:given_name>~<d:is_over_18>~'
    const kbjwt = await signKBJWT(presentation);

    const result = await verifySDJWT(`${presentation}${kbjwt}`, verifier, getHasher, { kb: { verifier: kbVerifier } });

    expect(result).toMatchObject({ given_name: 'Max', is_over_18: true });
  });

  describe('Key Binding JWT', () => {
    it('rejects a KB-JWT whose typ header is not kb+jwt', async () => {
      const presentation = await issue();

      // Everything is correct here except the header.
      const kbjwt = await signKBJWT(presentation, 'jwt');

      await expect(
        verifySDJWT(`${presentation}${kbjwt}`, verifier, getHasher, { kb: { verifier: kbVerifier } }),
      ).rejects.toThrow("expected typ 'kb+jwt', received 'jwt'");
    });
  });
});
