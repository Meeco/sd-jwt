import { SD_DIGEST, SD_LIST_PREFIX } from './constants';
import { Disclosure, DisclosureClaim, Hasher, SaltGenerator, SdDigestHashmap, UnverifiedJWT } from './types';

export function generateSalt(length: number): string {
  let salt = '';
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  for (let i = 0; i < length; i++) {
    salt += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return salt;
}

export function base64encode(input: string | Uint8Array): string {
  return Buffer.from(input).toString('base64url');
}

export function base64decode(input: string): string {
  return Buffer.from(input, 'base64url').toString();
}

// no verification
export function decodeJWT(input: string): UnverifiedJWT {
  if (typeof input !== 'string') {
    throw new Error('Invalid input');
  }

  const { 0: header, 1: payload, 2: signature, length } = input.split('.');
  if (length < 3) {
    throw new Error('Invalid JWT');
  }

  return {
    header: JSON.parse(base64decode(header)),
    payload: JSON.parse(base64decode(payload)),
    signature,
  };
}

/**
 * Helpers for UnpackSDJWT
 */
export const decodeDisclosure = (disclosures: string[]): Array<Disclosure> => {
  return disclosures.map((d) => {
    const decoded = JSON.parse(base64decode(d));

    let key;
    let value;

    // if disclosure is a value in an array
    // [<SALT>, <VALUE>]
    if (decoded.length == 2) {
      value = decoded[1];
    }
    // if disclosure is a value in an object
    // [<SALT>, <KEY>, <VALUE>]
    if (decoded.length == 3) {
      key = decoded[1];
      value = decoded[2];
    }

    return {
      disclosure: d,
      key,
      value,
    };
  });
};

export const createHashMapping = (disclosures: Disclosure[], hasher: Hasher): SdDigestHashmap => {
  const map = {};
  disclosures.forEach((d) => {
    const digest = hasher(d.disclosure);
    map[digest] = d;
  });
  return map;
};

/**
 * Iterates through an array
 * inserts claim if disclosed
 * removes any undisclosed claims
 */
export const unpackArray = ({ arr, map }) => {
  const unpackedArray = [];
  arr.forEach((item) => {
    if (item instanceof Object) {
      // if Array item is { '...': <SD_HASH_DIGEST> }
      if (item[SD_LIST_PREFIX]) {
        const hash = item[SD_LIST_PREFIX];
        const disclosed = map[hash];
        if (disclosed) {
          unpackedArray.push(disclosed.value);
        }
      } else {
        // unpack recursively
        unpackedArray.push(unpack({ obj: item, map }));
      }
    } else {
      unpackedArray.push(item);
    }
  });
  return unpackedArray;
};

/**
 * Iterates through an object
 * recursively unpack any child object or array
 * inserts claims if disclosed
 * removes any undisclosed claims
 */
export const unpack = ({ obj, map }) => {
  if (obj instanceof Object) {
    if (obj instanceof Array) {
      return unpackArray({ arr: obj, map });
    }

    for (const key in obj) {
      // if obj property value is an object
      // recursively unpack
      if (key !== SD_DIGEST && key !== SD_LIST_PREFIX && obj[key] instanceof Object) {
        obj[key] = unpack({ obj: obj[key], map });
      }
    }

    if (obj[SD_DIGEST]) {
      obj[SD_DIGEST].forEach((hash) => {
        const disclosed = map[hash];
        if (disclosed) {
          obj[disclosed.key] = unpack({ obj: disclosed.value, map });
        }
      });
      delete obj[SD_DIGEST];
    }
  }
  return obj;
};

/**
 * Helpers for packSDJWT
 */
export const createDisclosure = async (
  claim: DisclosureClaim,
  hasher: Hasher,
  options?: {
    generateSalt?: SaltGenerator;
  },
): Promise<{
  hash: string;
  disclosure: string;
}> => {
  let disclosureArray;
  const saltGenerator = options?.generateSalt ? options.generateSalt : generateSalt;
  const salt = saltGenerator(16);
  if (claim.key) {
    disclosureArray = [salt, claim.key, claim.value];
  } else {
    disclosureArray = [salt, claim.value];
  }

  const disclosure = base64encode(JSON.stringify(disclosureArray));
  const hash = hasher(disclosure);
  return {
    hash,
    disclosure,
  };
};
