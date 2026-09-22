import crypto from 'crypto';
import { importJWK, jwtVerify, SignJWT } from 'jose';
import { base64encode, decodeJWT } from './helpers';
import { issueSDJWT } from './issuer';
import { getExamples, getIssuerKey, loadPresentation, loadVerifiedContents } from './test-utils/helpers';
import { ISSUER_KEYPAIR } from './test-utils/params';
import { VerifySDJWTOptions } from './types';
import { verifySDJWT } from './verifier';

const EXAMPLE_WITH_KEY_BINDING = 'complex_ekyc';
const EXAMPLE_WITHOUT_KEY_BINDING = 'address_only_recursive';

const examples = getExamples();

const getHasher = (hashAlg) => {
  let hasher;
  // Default Hasher = Hasher for SHA-256
  if (!hashAlg || hashAlg.toLowerCase() === 'sha-256') {
    hasher = (data) => {
      const digest = crypto.createHash('sha256').update(data).digest();
      return base64encode(digest);
    };
  }
  return Promise.resolve(hasher);
};

describe('verifySDJWT', () => {
  let verifier;

  const getKbVerifier = (expectedAud, expectedNonce) => {
    return async (kbjwt, holderJWK) => {
      const { header, payload } = decodeJWT(kbjwt);

      if (expectedAud || expectedNonce) {
        if (payload.aud !== expectedAud) {
          throw new Error('aud mismatch');
        }
        if (payload.nonce !== expectedNonce) {
          throw new Error('nonce mismatch');
        }
      }

      const holderKey = await importJWK(holderJWK, header.alg);
      const verifiedKbJWT = await jwtVerify(kbjwt, holderKey);

      return !!verifiedKbJWT;
    };
  };

  beforeAll(() => {
    verifier = async (jwt) => {
      const key = await getIssuerKey();
      return jwtVerify(jwt, key);
    };
  });

  it.each(examples)('should be able to verify %s', async (example) => {
    const presentation = await loadPresentation(example);
    const expectedResult = await loadVerifiedContents(example);

    // Some examples carry a KB-JWT from a draft that predates sd_hash,
    // so it can no longer be verified. Key binding is covered by
    // verification-gaps.spec.ts; here only the Issuer-signed part is checked.
    const presentationWithoutKBJWT = presentation.slice(0, presentation.lastIndexOf('~') + 1);

    const result = await verifySDJWT(presentationWithoutKBJWT, verifier, getHasher);
    expect(result).toEqual(expectedResult);
  });

  it('should error when checking nonce and aud without a keybind', async () => {
    const example = EXAMPLE_WITHOUT_KEY_BINDING;
    const sdjwt = await loadPresentation(example);

    const kbOpts: VerifySDJWTOptions['kb'] = {
      verifier: () => Promise.resolve(true),
    };

    await expect(verifySDJWT(sdjwt, verifier, getHasher, { kb: kbOpts })).rejects.toThrow();
  });

  it('should error when checking with an incorrect nonce', async () => {
    const example = EXAMPLE_WITH_KEY_BINDING;
    const sdjwt = await loadPresentation(example);

    const kbOpts: VerifySDJWTOptions['kb'] = {
      verifier: getKbVerifier('invalid_aud', 'invalid_nonce'),
    };

    await expect(verifySDJWT(sdjwt, verifier, getHasher, { kb: kbOpts })).rejects.toThrow();
  });

  it('should reject a presentation containing a disclosure with invalid UTF-8 bytes', async () => {
    const signer = async (header, payload) => {
      const issuerPrivateKey = await importJWK(ISSUER_KEYPAIR.PRIVATE_KEY_JWK, header.alg);
      return (await new SignJWT(payload).setProtectedHeader(header).sign(issuerPrivateKey)).split('.').pop();
    };

    const hasher = (data) => {
      const digest = crypto.createHash('sha256').update(data).digest();
      return base64encode(digest);
    };

    const payload = {
      iss: 'https://example.com/issuer',
      sub: 'subject-id',
      name: 'John Doe',
    };

    const sdjwt = await issueSDJWT(
      { alg: 'ES256' },
      payload,
      { _sd: ['name'] },
      { hash: { alg: 'sha-256', callback: hasher }, signer },
    );

    // Corrupt the sole disclosure by replacing its base64url text with bytes
    // that don't decode as valid UTF-8.
    // Also see https://github.com/openwallet-foundation/sd-jwt-js/security/advisories/GHSA-f9j6-8p6x-r9j6
    const jwtPart = sdjwt.split('~')[0];
    const invalidUtf8Disclosure = 'QULyQw'; // base64url of [0x41, 0x42, 0xF2, 0x43]
    const tampered = `${jwtPart}~${invalidUtf8Disclosure}~`;

    await expect(verifySDJWT(tampered, verifier, getHasher)).rejects.toThrow();
  });
});
