import { FORMAT_SEPARATOR, SD_DIGEST, SD_LIST_PREFIX } from './constants.js';
import { CreateDecoyError, DecodeJWTError } from './errors.js';
import * as base64url from './runtime/base64url.js';
import {
  CompactSDJWT,
  Disclosure,
  DisclosureClaim,
  DisclosureMap,
  Hasher,
  SaltGenerator,
  SdDigestHashmap,
  UnverifiedJWT,
} from './types.js';

const decoder = new TextDecoder();

export function generateSalt(length: number): string {
  let salt = '';
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  for (let i = 0; i < length; i++) {
    salt += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return salt;
}

export function base64encode(input: string | Uint8Array): string {
  return base64url.encode(input);
}

export function base64decode(input: string): string {
  return decoder.decode(base64url.decode(input));
}

export function isObject(input: any): boolean {
  return typeof input === 'object' && input !== null && !Array.isArray(input);
}

// no verification
export function decodeJWT(input: string): UnverifiedJWT {
  if (typeof input !== 'string') {
    throw new DecodeJWTError('Invalid input');
  }

  const { 0: header, 1: payload, 2: signature, length } = input.split('.');
  if (length !== 3) {
    throw new DecodeJWTError('Invalid JWT as input');
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
export const decodeDisclosures = (disclosures: string[]): Array<Disclosure> => {
  return disclosures.map((d) => decodeDisclosure(d));
};

export const decodeDisclosure = (disclosure: string): Disclosure => {
  const decoded = JSON.parse(base64decode(disclosure));

  // if disclosure is a value in an array
  // [<SALT>, <VALUE>]
  if (decoded.length == 2) {
    return {
      disclosure,
      key: null,
      value: decoded[1],
    };
  }

  // if disclosure is a value in an object
  // [<SALT>, <KEY>, <VALUE>]
  if (decoded.length == 3) {
    return {
      disclosure,
      key: decoded[1],
      value: decoded[2],
    };
  }
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
  const unpackedArray: any[] = [];
  arr.forEach((item) => {
    if (item instanceof Object) {
      // if Array item is { '...': <SD_HASH_DIGEST> }
      if (item[SD_LIST_PREFIX]) {
        const hash = item[SD_LIST_PREFIX];
        const disclosed = map[hash];
        if (disclosed) {
          unpackedArray.push(unpack({ obj: disclosed.value, map }));
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

    const { _sd, ...payload } = obj;
    const claims = {};
    if (_sd) {
      _sd.forEach((hash) => {
        const disclosed = map[hash];
        if (disclosed) {
          claims[disclosed.key] = unpack({ obj: disclosed.value, map });
        }
      });
    }

    return Object.assign(payload, claims);
  }
  return obj;
};

/**
 * Helpers for packSDJWT
 */

export const createDisclosure = (
  claim: DisclosureClaim,
  hasher: Hasher,
  options?: {
    generateSalt?: SaltGenerator;
  },
): {
  hash: string;
  disclosure: string;
} => {
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

/**
 * Helpers for createSDMap
 */
const getParentSD = (disclosure: string, hasher: Hasher, hashmap: Record<string, string>): string[] => {
  const hash = hasher(disclosure);
  const parent = hashmap[hash];

  if (!parent) {
    return [];
  }

  if (hashmap[parent]) {
    return [parent].concat(getParentSD(parent, hasher, hashmap));
  }

  return [parent];
};

export const createDisclosureMap = (disclosures: Disclosure[], hasher: Hasher): DisclosureMap => {
  const map: DisclosureMap = {};
  const parentMap: Record<string, string> = {};

  disclosures.forEach(({ disclosure, value }) => {
    if (value && value._sd) {
      value._sd.forEach((sd: string) => {
        parentMap[sd] = disclosure;
      });
    }
  });

  disclosures.forEach(({ disclosure, value }) => {
    const parent = getParentSD(disclosure, hasher, parentMap);
    const hash = hasher(disclosure);

    map[hash] = {
      disclosure,
      value,
      parentDisclosures: parent,
    };
  });

  return map;
};

export const unpackArrayClaims = (arr: Array<any>, map: SdDigestHashmap) => {
  const unpackedArray: any[] = [];

  arr.forEach((item) => {
    if (item instanceof Object) {
      // if Array item is { '...': <SD_HASH_DIGEST> }
      if (item[SD_LIST_PREFIX]) {
        const hash = item[SD_LIST_PREFIX];
        const disclosed = map[hash];

        if (disclosed) {
          unpackedArray.push({
            '...': unpackClaims(disclosed.value, map),
            _sd: hash,
          });
        }
      } else {
        // unpack recursively
        const claims = unpackClaims(item, map);
        if (Object.keys(claims).length > 0) {
          unpackedArray.push(claims);
        } else {
          unpackedArray.push(null);
        }
      }
    } else {
      unpackedArray.push(null);
    }
  });

  return unpackedArray;
};

export const unpackClaims = (obj: any, map: SdDigestHashmap) => {
  if (obj instanceof Array) {
    return unpackArrayClaims(obj, map);
  }

  if (!isObject(obj)) {
    return {};
  }

  const claims = {};
  for (const key in obj) {
    // if obj property value is an object or array
    // recursively unpack
    if (key !== SD_DIGEST && key !== SD_LIST_PREFIX && obj[key] instanceof Object) {
      const claim = unpackClaims(obj[key], map);
      if (Object.keys(claim).length > 0) {
        claims[key] = claim;
      }
    }
  }

  if (obj._sd) {
    obj._sd.forEach((hash: string) => {
      const disclosed = map[hash];
      if (disclosed) {
        claims[disclosed.key] = { _sd: hash };
      }
    });
  }

  return claims;
};

export const combineSDJWT = (jwt: string, disclosures: string[], kbjwt?: string): CompactSDJWT => {
  let combined: CompactSDJWT = jwt;

  if (disclosures.length > 0) {
    combined += FORMAT_SEPARATOR + disclosures.join(FORMAT_SEPARATOR);
  }

  combined += FORMAT_SEPARATOR;

  if (kbjwt) {
    combined += kbjwt;
  }

  return combined;
};

export const createDecoy = (count: number, hasher: Hasher, saltGenerator: SaltGenerator = generateSalt): string[] => {
  if (count < 0) {
    throw new CreateDecoyError('decoy count must not be less than zero');
  }

  const decoys = [];

  for (let i = 0; i < count; i++) {
    const salt = saltGenerator(16);
    const decoy = hasher(salt);
    decoys.push(decoy);
  }

  return decoys;
};
