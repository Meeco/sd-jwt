import { base64url } from 'jose';
import * as crypto from 'crypto';
import { decodeSDJWT, packSDJWT, unpackSDJWT } from './common';
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

describe('packSDJWT', () => {
  let hasher;
  let generateSalt;

  beforeAll(() => {
    hasher = (data) => {
      const digest = crypto.createHash('sha256').update(data).digest().toString();
      const hash = base64url.encode(digest);
      return Promise.resolve(hash);
    };

    generateSalt = () => 'salt';
  });

  it('should be able to pack a simple claim', async () => {
    const claims = { id: 123 };
    const disclosureFrame = { _sd: ['id'] };
    const { claims: result, disclosures } = await packSDJWT(claims, disclosureFrame, hasher, { generateSalt });

    const disclosureArray = ['salt', 'id', 123];
    const expectedDisclosure = base64url.encode(JSON.stringify(disclosureArray));

    expect(disclosures.length).toEqual(1);
    expect(disclosures[0]).toEqual(expectedDisclosure);

    const expectedHash = await hasher(expectedDisclosure);
    expect(result).toEqual({ _sd: [expectedHash] });
  });

  it('should be able to pack an array', async () => {
    const claims = { items: [1, 2, 3] };
    const disclosureFrame = { items: [true, true, false] };
    const { claims: result, disclosures } = await packSDJWT(claims, disclosureFrame, hasher, { generateSalt });

    const disclosureArray = ['salt', 1];
    const expectedDisclosure = base64url.encode(JSON.stringify(disclosureArray));

    expect(disclosures.length).toEqual(2);
    expect(disclosures).toContain(expectedDisclosure);

    const expectedHash = await hasher(expectedDisclosure);
    const expectedResult = { '...': expectedHash };
    expect(result.items).toContainEqual(expectedResult);
  });

  it('should be able to recursively pack an array', async () => {
    const claims = { items: [1, 2, { id: 123 }] };
    const disclosureFrame = { items: [true, false, { _sd: ['id'], _self: true }] };
    const { claims: result, disclosures } = await packSDJWT(claims, disclosureFrame, hasher, { generateSalt });

    const disclosureArray = ['salt', 'id', 123];
    const disclosure = base64url.encode(JSON.stringify(disclosureArray));
    const hashedDisclosure = await hasher(disclosure);

    const recursiveDisclosure = ['salt', { _sd: [hashedDisclosure] }];
    const expectedDisclosure = base64url.encode(JSON.stringify(recursiveDisclosure));
    const expectedHash = await hasher(expectedDisclosure);

    expect(result.items).toContainEqual({ '...': expectedHash });
    expect(disclosures).toContain(expectedDisclosure);
  });

  it('should handle invalid inputs', async () => {
    // Missing claims
    await expect(packSDJWT(undefined, {}, hasher, {})).rejects.toThrow();

    // Missing disclosure frame
    await expect(packSDJWT({}, undefined, hasher, {})).rejects.toThrow();

    // @ts-expect-error Invalid claims
    await expect(packSDJWT(123, {}, hasher, {})).rejects.toThrow();

    // @ts-expect-error Invalid disclosure frame
    await expect(packSDJWT({}, 123, hasher, {})).rejects.toThrow();

    // Missing hasher
    await expect(packSDJWT({}, {}, undefined, {})).rejects.toThrow();

    // @ts-expect-error Invalid hasher
    await expect(packSDJWT({}, {}, 'invalid', {})).rejects.toThrow();

    // @ts-expect-error Missing options
    await expect(packSDJWT({}, {}, hasher)).rejects.toThrow();

    // @ts-expect-error Invalid options
    await expect(packSDJWT({}, {}, hasher, 123)).rejects.toThrow();
  });
});
