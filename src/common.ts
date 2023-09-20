import { FORMAT_SEPARATOR, SD_DIGEST, SD_HASH_ALG, SD_LIST_PREFIX } from './constants';
import {
  DecodeSDJWT,
  Disclosure,
  DisclosureClaim,
  DisclosureFrame,
  Hasher,
  PackSDJWT,
  SaltGenerator,
  SdDigestHashmap,
  UnpackSDJWT,
} from './types';
import { decodeJwt } from 'jose';
import * as crypto from 'crypto';
import { generateSalt, base64decode, base64encode } from './helpers';

const decodeDisclosure = (disclosures: string[]): Array<Disclosure> => {
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

/**
 * Splits the encoded SD-JWT into parts based on the FORMAT_SEPARATOR
 *
 * @param sdJWT base64 url encoded SD-JWT
 * @returns jwt input payload, an array of disclosures and a base64url encoded key binding jwt if present
 */
export const decodeSDJWT: DecodeSDJWT = (sdJWT) => {
  const s = sdJWT.split(FORMAT_SEPARATOR);

  // disclosures may be empty
  // but the separator before the key binding jwt must exist
  if (s.length < 2) {
    throw Error('Not a valid SD-JWT');
  }
  const unverifiedInputSdJwt = decodeJwt(s.shift() || '');
  const keyBindingJWT = s.pop();
  const disclosures = decodeDisclosure(s);

  return {
    unverifiedInputSdJwt,
    disclosures,
    keyBindingJWT,
  };
};

/**
 * Unpacking SD-JWT Claims from Disclosures
 */
const getHashAlgorithm = (sdJWT: any): string => {
  let hash_alg;
  switch (sdJWT[SD_HASH_ALG]?.toLowerCase()) {
    case 'sha-256':
    default:
      hash_alg = 'sha256';
  }
  return hash_alg;
};

const createHashMapping = (disclosures: Disclosure[], hash_alg: string): SdDigestHashmap => {
  const map = {};
  disclosures.forEach((d) => {
    const digest = crypto.createHash(hash_alg).update(d.disclosure).digest();
    map[base64encode(digest)] = d;
  });
  return map;
};

/**
 * Iterates through an array
 * inserts claim if disclosed
 * removes any undisclosed claims
 */
const unpackArray = ({ arr, map }) => {
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
const unpack = ({ obj, map }) => {
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
 * Replaces _sd digests present in the SD-JWT with disclosed claims
 *
 * @param sdJWT SD-JWT
 * @param disclosures hash map of disclosures
 * @returns sd-jwt with all disclosed claims
 */
export const unpackSDJWT: UnpackSDJWT = (sdJWT, disclosures) => {
  const hash_alg = getHashAlgorithm(sdJWT);
  const map = createHashMapping(disclosures, hash_alg);

  delete sdJWT[SD_HASH_ALG];
  return unpack({ obj: sdJWT, map });
};

const createDisclosure = async (
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
  const hash = await hasher(disclosure);
  return {
    hash,
    disclosure,
  };
};

/**
 * Creates a SD-JWT from claims and disclosureFrame definition
 *
 * @param claims
 * @param disclosureFrame declares which properties to be selectively disclosable
 * @param hasher
 * @returns
 */
export const packSDJWT: PackSDJWT = async (claims, disclosureFrame, hasher, options) => {
  if (typeof disclosureFrame !== 'object') {
    throw new Error('disclosureFrame is an invalid format');
  }
  if (!disclosureFrame) {
    throw new Error('no disclosureFrame found');
  }

  if (!hasher || typeof hasher !== 'function') {
    throw new Error('Hasher is required and must be a function');
  }

  if (!claims || typeof claims !== 'object') {
    throw new Error('no claims found');
  }

  const sd = disclosureFrame[SD_DIGEST];

  let packedClaims;
  let disclosures = [];

  if (claims instanceof Array) {
    packedClaims = [];

    const recursivelyPackedClaims = {};
    for (const key in disclosureFrame) {
      if (key !== SD_DIGEST) {
        const idx = parseInt(key);
        const packed = await packSDJWT(claims[idx], disclosureFrame[idx] as DisclosureFrame, hasher, options);
        recursivelyPackedClaims[idx] = packed.claims;
        disclosures = disclosures.concat(packed.disclosures);
      }
    }

    for (let i = 0; i < (claims as Array<any>).length; i++) {
      const claim = recursivelyPackedClaims[i] ? recursivelyPackedClaims[i] : claims[i];
      if (sd?.includes(i)) {
        const { hash, disclosure } = await createDisclosure({ value: claim }, hasher, options);
        packedClaims.push({ '...': hash });
        disclosures.push(disclosure);
      } else {
        packedClaims.push(claim);
      }
    }
  } else {
    packedClaims = {};
    // const decoys = disclosureFrame[DF_DECOY_COUNT];
    // delete disclosureFrame[DF_DECOY_COUNT];

    const recursivelyPackedClaims = {};
    for (const key in disclosureFrame) {
      if (key !== SD_DIGEST) {
        const packed = await packSDJWT(claims[key], disclosureFrame[key] as DisclosureFrame, hasher, options);
        recursivelyPackedClaims[key] = packed.claims;
        disclosures = disclosures.concat(packed.disclosures);
      }
    }

    const _sd = [];
    // if decoys exist, add decoy

    for (const key in claims) {
      const claim = recursivelyPackedClaims[key] ? recursivelyPackedClaims[key] : claims[key];
      if (sd?.includes(key)) {
        const { hash, disclosure } = await createDisclosure({ key, value: claim }, hasher, options);
        _sd.push(hash);
        disclosures.push(disclosure);
      } else {
        packedClaims[key] = claim;
      }
    }

    if (_sd.length > 0) {
      packedClaims[SD_DIGEST] = _sd;
    }
  }
  return { claims: packedClaims, disclosures };
};
