import crypto from 'crypto';
import { decodeSDJWT, packSDJWT, unpackSDJWT } from './common';
import { base64encode } from './helpers';
import {
  createPayloadWithDisclosures,
  createTestDisclosurePackage,
  getExamples,
  loadIssuedSDJWT,
  loadPresentation,
  loadSDJWTHeader,
  loadSDJWTPayload,
  loadVerifiedContents,
} from './test-utils/helpers';
import { INVALID_DISCLOSURE_ARRAY_SD_JWT_EXAMPLES, INVALID_JWT } from './test-utils/params';
import { DisclosureFrame } from './types';
import { FORBIDDEN_KEYS_IN_DISCLOSURE, SD_DIGEST, SD_LIST_PREFIX } from './constants';
import { PackSDJWTError, UnpackSDJWTError } from './errors';

const examples = getExamples();

const testHasher = (data: string | Uint8Array) => {
  const digest = crypto.createHash('sha256').update(data).digest();
  return base64encode(digest);
};

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
      hasher = testHasher;
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

  it('should reject conflicting claims at same level', async () => {
    const permanentClaimKey = 'user_status';
    const saltForTest = 'salt';
    const disclosureArray = [saltForTest, permanentClaimKey, 'value_to_be_rejected'];

    const { digest, decodedDisclosure } = createTestDisclosurePackage(disclosureArray, testHasher);
    const jwtPayloadWithConflict = createPayloadWithDisclosures([{ digest }], {
      [permanentClaimKey]: 'active_in_payload',
      another_claim: 'some other data',
    });

    const disclosuresForUnpack = [decodedDisclosure];
    const unpackPromise = unpackSDJWT(jwtPayloadWithConflict, disclosuresForUnpack, getHasher);

    await expect(unpackPromise).rejects.toThrow(UnpackSDJWTError);
    await expect(unpackPromise).rejects.toThrow(
      `Claim name conflict: Disclosed claim "${permanentClaimKey}" already exists as a property at this level.`,
    );
  });

  it('should reject if a disclosure for an object property provides an invalid key type', async () => {
    for (const { disclosureArray } of INVALID_DISCLOSURE_ARRAY_SD_JWT_EXAMPLES) {
      const rawDisclosureString = JSON.stringify(disclosureArray);
      const encodedDisclosureString = base64encode(rawDisclosureString);
      const digestForBadDisclosure = testHasher(encodedDisclosureString);

      const { digest, decodedDisclosure } = createTestDisclosurePackage(disclosureArray, testHasher);
      const jwtPayload = createPayloadWithDisclosures([{ digest }], {
        [SD_DIGEST]: [digestForBadDisclosure],
      });

      const disclosuresForUnpack = [decodedDisclosure];
      const unpackPromise = unpackSDJWT(jwtPayload, disclosuresForUnpack, getHasher);

      await expect(unpackPromise).rejects.toThrow(UnpackSDJWTError);
      await expect(unpackPromise).rejects.toThrow(`Disclosed claim key must be a non-empty string`);
    }
  });

  it('should reject if a disclosed claim name for an object property is a reserved keyword (_sd or ...)', async () => {
    const reservedKeyScenarios = FORBIDDEN_KEYS_IN_DISCLOSURE;

    for (const reservedKey of reservedKeyScenarios) {
      const disclosureArray = ['salt', reservedKey, 'some_value'];

      const { digest, decodedDisclosure } = createTestDisclosurePackage(disclosureArray, testHasher);
      const jwtPayload = createPayloadWithDisclosures([{ digest }], {
        [SD_DIGEST]: [digest],
      });

      const disclosuresForUnpack = [decodedDisclosure];
      const unpackPromise = unpackSDJWT(jwtPayload, disclosuresForUnpack, getHasher);

      await expect(unpackPromise).rejects.toThrow(UnpackSDJWTError);
      await expect(unpackPromise).rejects.toThrow(
        `Disclosed Claim name cannot be one of the following: ${FORBIDDEN_KEYS_IN_DISCLOSURE.join(', ')}`,
      );
    }
  });

  it('should reject if a disclosure for an array element is not a 2-element array (e.g., has a key)', async () => {
    // This disclosure is 3 elements, making it invalid for an array item context
    const disclosureArray = ['salt', 'this_key_should_not_be_here', 'value'];

    const { digest, decodedDisclosure } = createTestDisclosurePackage(disclosureArray, testHasher);
    const jwtPayload = createPayloadWithDisclosures([{ digest }], {
      list_of_items: [{ [SD_LIST_PREFIX]: digest }],
    });

    const disclosuresForUnpack = [decodedDisclosure];
    const unpackPromise = unpackSDJWT(jwtPayload, disclosuresForUnpack, getHasher);

    await expect(unpackPromise).rejects.toThrow(UnpackSDJWTError);
    await expect(unpackPromise).rejects.toThrow(
      `Invalid disclosure format for array element: expected 2 elements (salt, value)`,
    );
  });
});

describe('packSDJWT', () => {
  const generateSalt = () => 'salt';

  const createDisclosure = (array) => {
    const disclosure = base64encode(JSON.stringify(array));
    const hash = testHasher(disclosure);
    return {
      hash,
      disclosure,
    };
  };

  it('should be able to pack a simple claim', async () => {
    const claims = { id: 123 };
    const disclosureFrame: DisclosureFrame = { _sd: ['id'] };
    const { claims: result, disclosures } = await packSDJWT(claims, disclosureFrame, testHasher, { generateSalt });

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
    const { claims: result, disclosures } = await packSDJWT(claims, disclosureFrame, testHasher, { generateSalt });

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
    const { claims: result, disclosures } = await packSDJWT(claims, disclosureFrame, testHasher, { generateSalt });

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

    const { claims: result, disclosures } = await packSDJWT(claims, disclosureFrame, testHasher, { generateSalt });

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
    const { claims: result, disclosures } = await packSDJWT(claims, disclosureFrame, testHasher, { generateSalt });

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

    const { disclosures: disc1 } = await packSDJWT(claims, df1, testHasher, { generateSalt });
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

    const { disclosures: disc2 } = await packSDJWT(claims, df2, testHasher, { generateSalt });
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

    const { disclosures: disc3 } = await packSDJWT(claims, df3, testHasher, { generateSalt });
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

    const { disclosures: disc4 } = await packSDJWT(claims, df4, testHasher, { generateSalt });
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

    const { claims: result, disclosures: disc5 } = await packSDJWT(claims, df5, testHasher, { generateSalt });
    expect(disc5.length).toEqual(13);
    expect(disc5).toEqual(expect.arrayContaining(disc4));

    expect(result?._sd?.length).toEqual(3);
  });

  it('should handle invalid inputs', async () => {
    // Missing claims
    await expect(packSDJWT(undefined, {}, testHasher, {})).rejects.toThrow();

    // Missing disclosure frame
    await expect(packSDJWT({}, undefined, testHasher, {})).rejects.toThrow();

    // @ts-expect-error Invalid claims
    await expect(packSDJWT(123, {}, testHasher, {})).rejects.toThrow();

    // @ts-expect-error Invalid disclosure frame
    await expect(packSDJWT({}, 123, testHasher, {})).rejects.toThrow();

    // Missing hasher
    await expect(packSDJWT({}, {}, undefined, {})).rejects.toThrow();

    // @ts-expect-error Invalid hasher
    await expect(packSDJWT({}, {}, 'invalid', {})).rejects.toThrow();
  });

  it('should handle restricted claims, SD_LIST_PREFIX', async () => {
    const claims = {
      [SD_LIST_PREFIX]: 'restricted key',
    };

    const disclosureFrame = {
      [SD_DIGEST]: ['...'],
    };
    await expect(packSDJWT(claims, disclosureFrame, testHasher, {})).rejects.toThrow(
      'Claim name cannot be one of the following: _sd, ...',
    );
  });

  it('should handle restricted claims, SD_DIGEST', async () => {
    const claims = {
      [SD_DIGEST]: 'restricted key',
    };

    const disclosureFrame = {
      [SD_DIGEST]: ['_sd'],
    };
    await expect(packSDJWT(claims, disclosureFrame, testHasher, {})).rejects.toThrow(
      'Claim name cannot be one of the following: _sd, ...',
    );
  });

  it('should throw an error for duplicate digests in object array', async () => {
    const claims = {
      items: ['same_string_payload', 'same_string_payload'],
    };
    const disclosureFrame: DisclosureFrame = {
      items: { [SD_DIGEST]: [0, 1] },
    };

    await expect(packSDJWT(claims, disclosureFrame, testHasher, { generateSalt })).rejects.toThrow(PackSDJWTError);
  });

  it('should throw an error for duplicate digests in string array', async () => {
    const claims = { id: 123 };
    const disclosureFrame: DisclosureFrame = { _sd: ['id'], _decoyCount: 5 };
    // Static salt ensures decoys will have the same hash
    await expect(packSDJWT(claims, disclosureFrame, testHasher, { generateSalt })).rejects.toThrow(PackSDJWTError);
  });

  describe('decoys', () => {
    // Random salt ensures decoys will have the unique hash
    const uniqueGenerateSalt = () => `salt-${Math.random().toString(36).substring(2, 15)}`;

    it('should be able to generate decoys', async () => {
      const claims = { id: 123 };
      const disclosureFrame: DisclosureFrame = { _sd: ['id'], _sd_decoy: 5 };
      const { claims: result, disclosures } = await packSDJWT(claims, disclosureFrame, testHasher, {
        generateSalt: uniqueGenerateSalt,
      });

      expect(disclosures.length).toBe(1);
      expect(result._sd.length).toBe(6);
    });

    it('still supports old _decoyCount parameter', async () => {
      const claims = { id: 123 };
      const disclosureFrame: DisclosureFrame = { _sd: ['id'], _decoyCount: 5 };
      const { claims: result, disclosures } = await packSDJWT(claims, disclosureFrame, testHasher, {
        generateSalt: uniqueGenerateSalt,
      });

      expect(disclosures.length).toBe(1);
      expect(result._sd.length).toBe(6);
    });

    it('should be able to generate decoys in an array', async () => {
      const claims = { arr: [1, 2, 3] };
      const disclosureFrame: DisclosureFrame = { arr: { _sd: [0, 1, 2], _sd_decoy: 5 } };
      const { claims: result, disclosures } = await packSDJWT(claims, disclosureFrame, testHasher, {
        generateSalt: uniqueGenerateSalt,
      });

      expect(disclosures.length).toBe(3);
      expect(result.arr.length).toBe(8);
    });

    it('throws error if both _sd_decoy and _decoyCount are provided', () => {
      const claims = { id: 123 };
      const disclosureFrame: DisclosureFrame = { _sd: ['id'], _sd_decoy: 1, _decoyCount: 2 };

      expect(packSDJWT(claims, disclosureFrame, testHasher, { generateSalt: uniqueGenerateSalt })).rejects.toThrow();
    });

    it('should throw an error when provided with a negative decoy count', () => {
      const claims = { id: 123 };
      const disclosureFrame = { _sd: ['id'], _sd_decoy: -5 };

      expect(packSDJWT(claims, disclosureFrame, testHasher, { generateSalt: uniqueGenerateSalt })).rejects.toThrow();
    });
  });
});
