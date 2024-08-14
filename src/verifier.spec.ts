import crypto from 'crypto';
import { importJWK, jwtVerify } from 'jose';
import { base64encode, decodeJWT } from './helpers';
import {
  getExamples,
  getIssuerKey,
  loadKeyBindingJWT,
  loadPresentation,
  loadVerifiedContents,
} from './test-utils/helpers';
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
    const sdjwt = await loadPresentation(example);
    const expectedResult = await loadVerifiedContents(example);
    const kbjwt = await loadKeyBindingJWT(example);

    let opts;
    const kbjwtExist = !!kbjwt && typeof kbjwt === 'object' && Object.keys(kbjwt).length > 0;
    if (expectedResult.cnf && kbjwtExist) {
      opts = {
        kb: {
          verifier: getKbVerifier(kbjwt.aud, kbjwt.nonce),
        },
      };
    }
    const result = await verifySDJWT(sdjwt, verifier, getHasher, opts);
    expect(result).toEqual(expectedResult);
  });

  xit('should error when checking nonce and aud without a keybind', async () => {
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
});
