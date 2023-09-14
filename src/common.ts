import { FORMAT_SEPARATOR, SD_DIGEST, SD_HASH_ALG, SD_LIST_PREFIX } from './constants';
import { DecodeSDJWT, Disclosure, SdDigestHashmap, UnpackSDJWT } from './types';
import { base64url, decodeJwt } from 'jose';
import * as crypto from 'crypto';

const decodeDisclosure = (disclosures: string[]): Array<Disclosure> => {
  return disclosures.map((d) => {
    const decoded = JSON.parse(base64url.decode(d).toString());

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
  switch (sdJWT[SD_HASH_ALG].toLowerCase()) {
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
    map[base64url.encode(digest)] = d;
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
        // Only add item if disclosed
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
    // If obj is an array, removed undisclosed claims
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
      // append disclosure that matches the sd_digest hash into the object
      obj[SD_DIGEST].forEach((hash) => {
        const disclosed = map[hash];
        if (disclosed) {
          obj[disclosed.key] = unpack({ obj: disclosed.value, map });
        }
      });
      // remove SD_DIGEST property
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

  // remove SD_HASH_ALG property
  delete sdJWT[SD_HASH_ALG];
  return unpack({ obj: sdJWT, map });
};
