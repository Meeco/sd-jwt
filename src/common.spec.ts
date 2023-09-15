import { decodeSDJWT, unpackSDJWT } from './common';
import {
  getExamples,
  loadIssuedSDJWT,
  loadPresentation,
  loadSDJWTPayload,
  loadVerifiedContents,
} from './test-utils/helpers';
import { INVALID_JWT } from './test-utils/params';

const examples = getExamples();

describe('decodeSDJWT', () => {
  it.each(examples)('should get payload %s', async (example) => {
    const sdjwt = await loadIssuedSDJWT(example);
    const expectedJWTPayload = await loadSDJWTPayload(example);

    const { unverifiedInputSdJwt: result } = decodeSDJWT(sdjwt);
    expect(result).toEqual(expectedJWTPayload);
  });

  it('should throw an error for invalid SD-JWT', () => {
    expect(() => {
      decodeSDJWT(INVALID_JWT);
    }).toThrowError();
  });
});

describe('unpackSDJWT', () => {
  it.each(examples)('should unpack %s', async (example) => {
    const sdjwt = await loadPresentation(example);
    const expectedSDJWT = await loadVerifiedContents(example);

    const { unverifiedInputSdJwt, disclosures } = decodeSDJWT(sdjwt);
    const result = unpackSDJWT(unverifiedInputSdJwt, disclosures);
    expect(result).toEqual(expectedSDJWT);
  });
});
