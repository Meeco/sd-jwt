import { verifySDJWT } from './verifier';
import {
  getExamples,
  getIssuerKey,
  loadKeyBindingJWT,
  loadPresentation,
  loadVerifiedContents,
} from './test-utils/helpers';

const EXAMPLE_WITH_KEY_BINDING_JWT = 'complex_ekyc';
const EXAMPLE_WITHOUT_KEY_BINDING_JWT = 'address_only_recursive';

const examples = getExamples();

describe('verifySDJWT', () => {
  it.each(examples)('should be able to verify %s', async (example) => {
    const sdjwt = await loadPresentation(example);
    const expectedResult = await loadVerifiedContents(example);
    const kbjwt = await loadKeyBindingJWT(example);

    const options = {
      getIssuerKey,
      expected_nonce: kbjwt?.nonce,
      expected_aud: kbjwt?.aud,
    };

    const result = await verifySDJWT(sdjwt, options);
    expect(result).toEqual(expectedResult);
  });

  it('should error when checking nonce and aud without a keybind', async () => {
    const example = EXAMPLE_WITHOUT_KEY_BINDING_JWT;
    const sdjwt = await loadPresentation(example);

    const options = {
      getIssuerKey,
      expected_nonce: 'invalid_nonce',
      expected_aud: 'invalid_aud',
    };

    expect(async () => {
      await verifySDJWT(sdjwt, options);
    }).toThrowError;
  });

  it('should error when checking with an incorrect nonce', async () => {
    const example = EXAMPLE_WITH_KEY_BINDING_JWT;
    const sdjwt = await loadPresentation(example);

    const options = {
      getIssuerKey,
      expected_nonce: 'invalid_nonce',
      expected_aud: 'invalid_aud',
    };

    expect(async () => {
      await verifySDJWT(sdjwt, options);
    }).toThrowError;
  });

  it('fail to verify if invalid key is provided', async () => {
    const example = EXAMPLE_WITHOUT_KEY_BINDING_JWT;
    const sdjwt = await loadPresentation(example);

    const options = {
      getIssuerKey: () => Promise.resolve(undefined),
    };

    expect(async () => {
      await verifySDJWT(sdjwt, options);
    }).toThrowError;
  });
});
