import { FORMAT_SEPARATOR, SD_DIGEST, SD_HASH_ALG } from './constants';
import { DecodeSDJWT, Disclosure, SdDigestHashmap, UnpackSDJWT } from './types';
import { base64url, decodeJwt } from 'jose';
import * as crypto from 'crypto';

const decodeDisclosure = (disclosures: string[]): Array<Disclosure> => {
  return disclosures.map((d) => {
    const decoded = JSON.parse(base64url.decode(d).toString());
    return {
      disclosure: d,
      key: decoded[1],
      value: decoded[2],
    };
  });
};

export const decodeSDJWT: DecodeSDJWT = (sdJWT) => {
  const s = sdJWT.split(FORMAT_SEPARATOR);

  if (s.length < 3) {
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

const unpack = ({ obj, map }) => {
  for (const key in obj) {
    if (key !== SD_DIGEST && obj[key] instanceof Object) {
      obj[key] = unpack({ obj: obj[key], map });
    }

    if (obj[SD_DIGEST]) {
      obj._sd.forEach((hash) => {
        const disclosed = map[hash];
        if (disclosed) {
          obj[disclosed.key] = disclosed.value;
        }
      });
      delete obj[SD_DIGEST];
    }
  }
  return obj;
};

export const unpackSDJWT: UnpackSDJWT = (sdJWT, disclosures) => {
  const hash_alg = getHashAlgorithm(sdJWT);
  const map = createHashMapping(disclosures, hash_alg);
  return unpack({ obj: sdJWT, map });
};
