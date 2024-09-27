import crypto from 'crypto';
import { DisclosureFrame } from 'dist/types';
import { decodeSDJWT, packSDJWT, unpackSDJWT } from './common';
import { base64encode } from './helpers';
import {
  getExamples,
  loadIssuedSDJWT,
  loadPresentation,
  loadSDJWTHeader,
  loadSDJWTPayload,
  loadVerifiedContents,
} from './test-utils/helpers';
import { INVALID_JWT } from './test-utils/params';

const examples = getExamples();

describe('decodeSDJWT', () => {
  it.each(examples)('should get payload %s', async (example) => {
    const sdjwt = await loadIssuedSDJWT(example);
    const expectedJWTPayload = await loadSDJWTPayload(example);
    const expectedJWTHeader = await loadSDJWTHeader(example);

    const { unverifiedInputSDJWT: payload, header } = decodeSDJWT(sdjwt);

    expect(payload).toEqual(expectedJWTPayload);
    expect(header).toEqual(expectedJWTHeader);
  });

  it('should throw an error for invalid SD-JWT', () => {
    expect(() => {
      decodeSDJWT(INVALID_JWT);
    }).toThrow();
  });
});

describe('unpackSDJWT', () => {
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

  it.each(examples)('should unpack %s', async (example) => {
    const sdjwt = await loadPresentation(example);
    const expectedSDJWT = await loadVerifiedContents(example);

    const { unverifiedInputSDJWT, disclosures } = decodeSDJWT(sdjwt);
    const result = await unpackSDJWT(unverifiedInputSDJWT, disclosures, getHasher);
    expect(result).toEqual(expectedSDJWT);
  });
});

describe('packSDJWT', () => {
  const hasher = (data) => {
    const digest = crypto.createHash('sha256').update(data).digest();
    return base64encode(digest);
  };

  const generateSalt = () => 'salt';

  const createDisclosure = (array) => {
    const disclosure = base64encode(JSON.stringify(array));
    const hash = hasher(disclosure);
    return {
      hash,
      disclosure,
    };
  };

  it('should be able to pack a simple claim', async () => {
    const claims = { id: 123 };
    const disclosureFrame: DisclosureFrame = { _sd: ['id'] };
    const { claims: result, disclosures } = await packSDJWT(claims, disclosureFrame, hasher, { generateSalt });

    const disclosureArray = ['salt', 'id', 123];
    const { hash: expectedHash, disclosure: expectedDisclosure } = createDisclosure(disclosureArray);

    expect(disclosures.length).toEqual(1);
    expect(disclosures[0]).toEqual(expectedDisclosure);
    expect(result).toEqual({ _sd: [expectedHash] });
  });

  it('should be able to pack an array', async () => {
    const claims = { items: [1, 2, 3] };
    const disclosureFrame: DisclosureFrame = {
      items: { _sd: [0, 1] },
    };
    const { claims: result, disclosures } = await packSDJWT(claims, disclosureFrame, hasher, { generateSalt });

    const disclosureArray = ['salt', 1];
    const { hash: expectedHash, disclosure: expectedDisclosure } = createDisclosure(disclosureArray);

    expect(disclosures.length).toEqual(2);
    expect(disclosures).toContainEqual(expectedDisclosure);

    const expectedResult = { '...': expectedHash };
    expect(result.items).toContainEqual(expectedResult);
  });

  it('should be able to recursively pack an array', async () => {
    const claims = { items: [1, 2, { id: 123 }] };
    const disclosureFrame: DisclosureFrame = {
      items: {
        _sd: [0, 2],
        2: { _sd: ['id'] },
      },
    };
    const { claims: result, disclosures } = await packSDJWT(claims, disclosureFrame, hasher, { generateSalt });

    const disclosureArray = ['salt', 'id', 123];
    const { hash: hashedDisclosure } = createDisclosure(disclosureArray);

    const recursiveDisclosure = ['salt', { _sd: [hashedDisclosure] }];
    const { hash: expectedHash, disclosure: expectedDisclosure } = createDisclosure(recursiveDisclosure);

    expect(result.items).toContainEqual(2);
    expect(result.items).toContainEqual({ '...': expectedHash });
    expect(result.items.length).toEqual(3);

    expect(disclosures).toContain(expectedDisclosure);
    expect(disclosures.length).toEqual(3);
  });

  it('should be able to pack nested object', async () => {
    const claims = { items: { sub: { iss: 1, aud: 2 } } };
    const disclosureFrame: DisclosureFrame = {
      items: {
        sub: {
          _sd: ['iss'],
        },
      },
    };

    const { claims: result, disclosures } = await packSDJWT(claims, disclosureFrame, hasher, { generateSalt });

    const disclosureArray = ['salt', 'iss', 1];
    const { hash: expectedHash, disclosure: expectedDisclosure } = createDisclosure(disclosureArray);

    const expectedResult = {
      items: {
        sub: {
          _sd: [expectedHash],
          aud: 2,
        },
      },
    };
    expect(result).toEqual(expectedResult);
    expect(disclosures).toContain(expectedDisclosure);
  });

  it('should be able to pack arrays in array', async () => {
    const claims = {
      items: [[1, 2], 3],
    };
    const disclosureFrame: DisclosureFrame = {
      items: {
        _sd: [0],
        0: { _sd: [0, 1] },
      },
    };
    const { claims: result, disclosures } = await packSDJWT(claims, disclosureFrame, hasher, { generateSalt });

    const arr1 = ['salt', 1];
    const { hash: hash1 } = createDisclosure(arr1);
    const arr2 = ['salt', 2];
    const { hash: hash2 } = createDisclosure(arr2);

    const recursiveDisclosure = ['salt', [{ '...': hash1 }, { '...': hash2 }]];
    const { hash: expectedHash, disclosure: expectedDisclosure } = createDisclosure(recursiveDisclosure);

    expect(disclosures).toContain(expectedDisclosure);
    expect(disclosures.length).toEqual(3);

    expect(result.items).toContainEqual({ '...': expectedHash });
    expect(result.items.length).toEqual(2);
  });

  it('should be able to handle a complex structure', async () => {
    const claims = {
      id: 123,
      items: [[1, 2], 3],
      complex: [
        [{ id: 456 }, 'text', [1, 2, 3]],
        {
          iss: {
            id: 567,
            arr: [5, 6, [2, 4]],
          },
        },
      ],
    };

    const df1 = {
      complex: {
        1: { iss: { _sd: ['id'] } },
      },
    };

    const { disclosures: disc1 } = await packSDJWT(claims, df1, hasher, { generateSalt });
    expect(disc1.length).toEqual(1);

    // recursive disclosure on second item of 'complex'
    const df2 = {
      complex: {
        1: {
          _sd: ['iss'],
          iss: { _sd: ['id'] },
        },
      },
    };

    const { disclosures: disc2 } = await packSDJWT(claims, df2, hasher, { generateSalt });
    expect(disc2.length).toEqual(2);
    expect(disc2).toEqual(expect.arrayContaining(disc1));

    // recursive disclosure on first item of 'complex'
    const df3 = {
      complex: {
        0: {
          _sd: [0, 1, 2],
          0: { _sd: ['id'] },
          2: { _sd: [0, 2] },
        },
      },
    };

    const { disclosures: disc3 } = await packSDJWT(claims, df3, hasher, { generateSalt });
    expect(disc3.length).toEqual(6);

    // further recursion
    const df4 = {
      complex: {
        _sd: [0, 1],
        0: {
          _sd: [0, 1, 2],
          0: { _sd: ['id'] },
          2: { _sd: [0, 2] },
        },
        1: {
          _sd: ['iss'],
          iss: { _sd: ['id'] },
        },
      },
    };

    const { disclosures: disc4 } = await packSDJWT(claims, df4, hasher, { generateSalt });
    expect(disc4.length).toEqual(10);
    expect(disc4).toEqual(expect.arrayContaining(disc2));
    expect(disc4).toEqual(expect.arrayContaining(disc3));

    // further recursion
    const df5 = {
      _sd: ['id', 'items', 'complex'],
      complex: {
        _sd: [0, 1],
        0: {
          _sd: [0, 1, 2],
          0: { _sd: ['id'] },
          2: { _sd: [0, 2] },
        },
        1: {
          _sd: ['iss'],
          iss: { _sd: ['id'] },
        },
      },
    };

    const { claims: result, disclosures: disc5 } = await packSDJWT(claims, df5, hasher, { generateSalt });
    expect(disc5.length).toEqual(13);
    expect(disc5).toEqual(expect.arrayContaining(disc4));

    expect(result?._sd?.length).toEqual(3);
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
  });

  describe('decoys', () => {
    it('should be able to generate decoys', async () => {
      const claims = { id: 123 };
      const disclosureFrame: DisclosureFrame = { _sd: ['id'], _sd_decoy: 5 };
      const { claims: result, disclosures } = await packSDJWT(claims, disclosureFrame, hasher, { generateSalt });

      expect(disclosures.length).toBe(1);
      expect(result._sd.length).toBe(6);
    });

    it('still supports old _decoyCount parameter', async () => {
      const claims = { id: 123 };
      const disclosureFrame: DisclosureFrame = { _sd: ['id'], _decoyCount: 5 };
      const { claims: result, disclosures } = await packSDJWT(claims, disclosureFrame, hasher, { generateSalt });

      expect(disclosures.length).toBe(1);
      expect(result._sd.length).toBe(6);
    });

    it('should be able to generate decoys in an array', async () => {
      const claims = { arr: [1, 2, 3] };
      const disclosureFrame: DisclosureFrame = { arr: { _sd: [0, 1, 2], _sd_decoy: 5 } };
      const { claims: result, disclosures } = await packSDJWT(claims, disclosureFrame, hasher, { generateSalt });

      expect(disclosures.length).toBe(3);
      expect(result.arr.length).toBe(8);
    });

    it('throws error if both _sd_decoy and _decoyCount are provided', () => {
      const claims = { id: 123 };
      const disclosureFrame: DisclosureFrame = { _sd: ['id'], _sd_decoy: 1, _decoyCount: 2 };

      expect(packSDJWT(claims, disclosureFrame, hasher, { generateSalt })).rejects.toThrow();
    });

    it('should throw an error when provided with a negative decoy count', () => {
      const claims = { id: 123 };
      const disclosureFrame = { _sd: ['id'], _sd_decoy: -5 };

      expect(packSDJWT(claims, disclosureFrame, hasher, { generateSalt })).rejects.toThrow();
    });
  });
});
