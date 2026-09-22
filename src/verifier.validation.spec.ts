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

    it('rejects a presentation carrying a KB-JWT when no KB verifier is supplied', async () => {
      const presentation = await issue();
      const kbjwt = await signKBJWT(presentation);

      await expect(verifySDJWT(`${presentation}${kbjwt}`, verifier, getHasher)).rejects.toThrow(
        'Key Binding JWT found but no KB JWT verifier function was provided',
      );
    });

    it('requires a KB-JWT once a KB verifier is supplied', async () => {
      const presentation = await issue(); // no KB-JWT appended

      await expect(verifySDJWT(presentation, verifier, getHasher, { kb: { verifier: kbVerifier } })).rejects.toThrow(
        'No Key Binding JWT found',
      );

      // Without a KB verifier the same presentation verifies.
      const result = await verifySDJWT(presentation, verifier, getHasher);
      expect(result).toMatchObject({ given_name: 'Max', is_over_18: true });
    });

    // A KB-JWT signed over both disclosures is reused while presenting only one of them.
    it('rejects a presentation whose disclosures were removed after the KB-JWT was signed', async () => {
      const fullPresentation = await issue();
      const kbjwt = await signKBJWT(fullPresentation); // its sd_hash covers BOTH disclosures

      // '<jwt>~<d:given_name>~<d:is_over_18>~' -> ['<jwt>', '<d:given_name>', '<d:is_over_18>'].
      // filter(Boolean) drops the empty segment left by the trailing separator.
      const segments = fullPresentation.split('~').filter(Boolean);
      const issuerSignedJwt = segments[0];
      const allDisclosures = segments.slice(1);

      // Everything except the last disclosure (is_over_18).
      const keptDisclosures = allDisclosures.slice(0, -1);

      // Re-assemble a valid presentation - every one of them ends with a separator.
      const strippedPresentation = `${issuerSignedJwt}~${keptDisclosures.join('~')}~`;

      // The untouched KB-JWT, now appended to content it was never signed over.
      const strippedSdJwtKb = `${strippedPresentation}${kbjwt}`;

      await expect(verifySDJWT(strippedSdJwtKb, verifier, getHasher, { kb: { verifier: kbVerifier } })).rejects.toThrow(
        'Key Binding JWT sd_hash does not match the presented SD-JWT',
      );
    });

    // A KB-JWT signed over a minimal presentation is reused to present a disclosure the holder withheld.
    it('rejects a presentation carrying a disclosure the KB-JWT never covered', async () => {
      const fullPresentation = await issue();

      const segments = fullPresentation.split('~').filter(Boolean);
      const issuerSignedJwt = segments[0];
      const allDisclosures = segments.slice(1);

      // The holder withholds is_over_18 and shows given_name only.
      const shownDisclosures = allDisclosures.slice(0, 1);

      const minimalPresentation = `${issuerSignedJwt}~${shownDisclosures.join('~')}~`;
      const kbjwt = await signKBJWT(minimalPresentation); // its sd_hash covers ONE disclosure

      // The same KB-JWT, now appended to the full presentation the holder never signed over.
      const inflatedSdJwtKb = `${fullPresentation}${kbjwt}`;

      await expect(verifySDJWT(inflatedSdJwtKb, verifier, getHasher, { kb: { verifier: kbVerifier } })).rejects.toThrow(
        'Key Binding JWT sd_hash does not match the presented SD-JWT',
      );
    });

    it('rejects a KB-JWT without an sd_hash claim', async () => {
      const presentation = await issue();

      const kbjwtWithoutSdHash = await new SignJWT({ aud: AUDIENCE, nonce: NONCE, iat: Math.floor(Date.now() / 1000) })
        .setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' })
        .sign(holderPrivateKey);

      await expect(
        verifySDJWT(`${presentation}${kbjwtWithoutSdHash}`, verifier, getHasher, { kb: { verifier: kbVerifier } }),
      ).rejects.toThrow('Key Binding JWT sd_hash does not match the presented SD-JWT');
    });
  });
});
