import { verifySDJWT } from './verifier';
import {
  getExamples,
  getIssuerKey,
  loadKeyBindingJWT,
  loadPresentation,
  loadVerifiedContents,
} from './test-utils/helpers';
import { importJWK, jwtVerify } from 'jose';
import { decodeJWT } from './helpers';
import { VerifySdJwtOptions } from './types';

const EXAMPLE_WITH_KEY_BINDING = 'complex_ekyc';
const EXAMPLE_WITHOUT_KEY_BINDING = 'address_only_recursive';

const examples = getExamples();

describe('verifySDJWT', () => {
  let verifier;

  const getKbVerifier = async (holderJWK, expectedAud, expectedNonce) => {
    return async (kbjwt) => {
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

  beforeAll(async () => {
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
      const holderJWK = expectedResult.cnf.jwk;
      opts = {
        kb: {
          verifier: await getKbVerifier(holderJWK, kbjwt.aud, kbjwt.nonce),
        },
      };
    }
    const result = await verifySDJWT(sdjwt, verifier, opts);
    expect(result).toEqual(expectedResult);
  });

  it('should error when checking nonce and aud without a keybind', async () => {
    const example = EXAMPLE_WITHOUT_KEY_BINDING;
    const sdjwt = await loadPresentation(example);

    const kbOpts: VerifySdJwtOptions['kb'] = {
      verifier: () => Promise.resolve(true),
    };
    expect(async () => {
      await verifySDJWT(sdjwt, verifier, { kb: kbOpts });
    }).toThrowError;
  });

  it('should error when checking with an incorrect nonce', async () => {
    const example = EXAMPLE_WITH_KEY_BINDING;
    const expectedResult = await loadVerifiedContents(example);
    const sdjwt = await loadPresentation(example);

    const holderJWK = expectedResult.cnf.jwk;
    const kbOpts: VerifySdJwtOptions['kb'] = {
      verifier: await getKbVerifier(holderJWK, 'invalid_aud', 'invalid_nonce')
    };
    expect(async () => {
      await verifySDJWT(sdjwt, verifier, { kb: kbOpts });
    }).toThrowError;
  });
});
