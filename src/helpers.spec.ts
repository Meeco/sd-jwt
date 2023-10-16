import { CreateDecoyError } from './errors';
import { base64decode, base64encode, createDecoy, createDisclosureMap } from './helpers';
import crypto from 'crypto';

const disclosure: string[] = ['5a2W0_NrlEZzfqmk_7Pq-w', 'administeringCentre', 'Praxis Sommergarten'];
const encodedDisclosure: string =
  'WyI1YTJXMF9OcmxFWnpmcW1rXzdQcS13IiwiYWRtaW5pc3RlcmluZ0NlbnRyZSIsIlByYXhpcyBTb21tZXJnYXJ0ZW4iXQ';

describe('base64encode', () => {
  it('should encode a disclosureArray string', () => {
    const disclosureArray = JSON.stringify(disclosure);
    const encoded = base64encode(disclosureArray);
    expect(encoded).toEqual(encodedDisclosure);
  });
});

describe('base64decode', () => {
  it('should decode a base64url encoded string', () => {
    const decoded = base64decode(encodedDisclosure);
    expect(JSON.parse(decoded)).toEqual(disclosure);
  });
});

const hasher = (data) => {
  const digest = crypto.createHash('sha256').update(data).digest();
  return base64encode(digest);
};

describe('createDisclosureMap', () => {
  it('should be able to create a map with hash as the key', () => {
    const hash = hasher('disclosure');
    const disclosures = [
      {
        disclosure: 'disclosure',
        key: 'key',
        value: 'value',
      },
    ];
    const result = createDisclosureMap(disclosures, hasher);

    expect(result[hash].disclosure).toEqual('disclosure');
  });

  it('should be able to create a map of recursive SD', () => {
    const recursiveDigest = hasher('recursive');
    const disclosures = [
      {
        disclosure: 'parent',
        key: 'key1',
        value: {
          _sd: [recursiveDigest],
        },
      },
      {
        disclosure: 'recursive',
        key: 'key2',
        value: 'c',
      },
    ];
    const result = createDisclosureMap(disclosures, hasher);

    expect(result[recursiveDigest].parentDisclosures).toEqual(['parent']);
  });
});

describe('createDecoy', () => {
  it('should be able to create the correct number of decoys', () => {
    const decoys = createDecoy(3, hasher);

    expect(decoys.length).toEqual(3);
  });

  it('should throw an error when the number is less than 0', () => {
    expect(() => createDecoy(-5, hasher)).toThrow(CreateDecoyError);
  });

  it('should be able to create decoy with custom generateSaltFunction', () => {
    const generateSalt = jest.fn(() => 'salt');
    const hasher = jest.fn((data) => data);

    createDecoy(1, hasher, generateSalt);

    expect(generateSalt).toBeCalled();
    expect(hasher).toBeCalledWith('salt');
  });
});
