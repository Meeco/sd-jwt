import crypto from 'crypto';
import { compactVerify, exportJWK, generateKeyPair, importJWK, jwtVerify, SignJWT } from 'jose';
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

  const issue = (sdAlg = 'sha-256') =>
    issueSDJWT(
      { alg: 'ES256' },
      { iss: 'https://issuer.example.com', sub: 'subject-id', given_name: 'Max', is_over_18: true },
      { _sd: ['given_name', 'is_over_18'] },
      { hash: { alg: sdAlg, callback: hasher }, signer, cnf: { jwk: holderPublicJWK } },
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

    it('rejects a stale KB-JWT by default, and accepts it when the caller opts out', async () => {
      const presentation = await issue();

      const staleKBJWT = await new SignJWT({
        aud: AUDIENCE,
        nonce: NONCE,
        iat: Math.floor(Date.now() / 1000) - 3600,
        sd_hash: hasher(presentation),
      })
        .setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' })
        .sign(holderPrivateKey);

      await expect(
        verifySDJWT(`${presentation}${staleKBJWT}`, verifier, getHasher, { kb: { verifier: kbVerifier } }),
      ).rejects.toThrow('is not within 600s of now');

      const result = await verifySDJWT(`${presentation}${staleKBJWT}`, verifier, getHasher, {
        kb: { verifier: kbVerifier, iat: false },
      });
      expect(result).toMatchObject({ given_name: 'Max' });
    });

    it('accepts a KB-JWT within a window widened by the caller', async () => {
      const presentation = await issue();

      const halfAnHourOld = await new SignJWT({
        aud: AUDIENCE,
        nonce: NONCE,
        iat: Math.floor(Date.now() / 1000) - 1800,
        sd_hash: hasher(presentation),
      })
        .setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' })
        .sign(holderPrivateKey);

      const opts = { kb: { verifier: kbVerifier, iat: { skewSeconds: 3600 } } };
      const result = await verifySDJWT(`${presentation}${halfAnHourOld}`, verifier, getHasher, opts);

      expect(result).toMatchObject({ given_name: 'Max' });
    });

    it('rejects a KB-JWT without an iat claim', async () => {
      const presentation = await issue();

      const kbjwtWithoutIat = await new SignJWT({ aud: AUDIENCE, nonce: NONCE, sd_hash: hasher(presentation) })
        .setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' })
        .sign(holderPrivateKey);

      await expect(
        verifySDJWT(`${presentation}${kbjwtWithoutIat}`, verifier, getHasher, { kb: { verifier: kbVerifier } }),
      ).rejects.toThrow('Key Binding JWT has no iat claim');
    });
  });

  describe('_sd_alg', () => {
    it('rejects an unregistered _sd_alg without passing it to getHasher', async () => {
      const madeUpHashAlg = 'totally-made-up';
      const presentation = await issue(madeUpHashAlg);

      // A getHasher that ignores the algorithm it is asked for: the digests would
      // still resolve, because they were made with SHA-256.
      const requestedAlgs: string[] = [];
      const getHasherIgnoringAlg = (alg: string) => {
        requestedAlgs.push(alg);
        return Promise.resolve(hasher);
      };

      await expect(verifySDJWT(presentation, verifier, getHasherIgnoringAlg)).rejects.toThrow(
        `Unsupported _sd_alg '${madeUpHashAlg}'`,
      );

      expect(requestedAlgs).toEqual([]);
    });
  });

  describe('exp and nbf', () => {
    // Checks the signature and nothing else, so that only the library enforces the validity period.
    const signatureOnlyVerifier = async (jwt: string) => {
      const issuerPublicKey = await importJWK(ISSUER_KEYPAIR.PUBLIC_KEY_JWK, 'ES256');
      return !!(await compactVerify(jwt, issuerPublicKey));
    };

    const issueWithValidityPeriod = (claims: { exp?: number; nbf?: number }) =>
      issueSDJWT(
        { alg: 'ES256' },
        { iss: 'https://issuer.example.com', sub: 'subject-id', given_name: 'Max', ...claims },
        { _sd: ['given_name'] },
        { hash: { alg: 'sha-256', callback: hasher }, signer },
      );

    it('rejects an expired credential even when the verifier callback ignores exp', async () => {
      const expiredAnHourAgo = Math.floor(Date.now() / 1000) - 3600;
      const expiredCredential = await issueWithValidityPeriod({ exp: expiredAnHourAgo });

      await expect(verifySDJWT(expiredCredential, signatureOnlyVerifier, getHasher)).rejects.toThrow(
        `SD-JWT expired at ${expiredAnHourAgo}`,
      );
    });

    it('accepts an expired credential when the caller opts out', async () => {
      const expiredAnHourAgo = Math.floor(Date.now() / 1000) - 3600;
      const expiredCredential = await issueWithValidityPeriod({ exp: expiredAnHourAgo });

      // For callers that report expiry themselves rather than rejecting outright.
      const result = await verifySDJWT(expiredCredential, signatureOnlyVerifier, getHasher, { time: { skip: true } });

      expect(result).toMatchObject({ exp: expiredAnHourAgo, given_name: 'Max' });
    });

    it('accepts a credential that expired within the configured skew', async () => {
      const expiredAMinuteAgo = Math.floor(Date.now() / 1000) - 60;
      const expiredCredential = await issueWithValidityPeriod({ exp: expiredAMinuteAgo });

      const opts = { time: { skewSeconds: 300 } };
      const result = await verifySDJWT(expiredCredential, signatureOnlyVerifier, getHasher, opts);

      expect(result).toMatchObject({ exp: expiredAMinuteAgo, given_name: 'Max' });
    });

    it('rejects a credential that is not valid yet', async () => {
      const validInAnHour = Math.floor(Date.now() / 1000) + 3600;
      const futureCredential = await issueWithValidityPeriod({ nbf: validInAnHour });

      await expect(verifySDJWT(futureCredential, signatureOnlyVerifier, getHasher)).rejects.toThrow(
        `SD-JWT is not valid before ${validInAnHour}`,
      );
    });
  });
});
