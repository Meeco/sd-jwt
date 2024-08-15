import { DEFAULT_SD_HASH_ALG, FORMAT_SEPARATOR, SD_DECOY_COUNT, SD_DIGEST, SD_HASH_ALG } from './constants.js';
import { PackSDJWTError, SDJWTInvalidFormatError } from './errors.js';
import {
  createDecoy,
  createDisclosure,
  createHashMapping,
  decodeDisclosures,
  decodeJWT,
  isObject,
  unpack,
} from './helpers.js';
import { CompactSDJWT, DecodeSDJWT, DisclosureFrame, PackSDJWT, UnpackSDJWT } from './types.js';

/**
 * Splits compact SD-JWT into parts based on the FORMAT_SEPARATOR
 *
 * @param sdJWT
 * @returns {
 *  signedJWT,
 *  disclosures,
 *  kbJWT
 * }
 */
export const splitSDJWT = (sdjwt: CompactSDJWT) => {
  const separated = sdjwt.split(FORMAT_SEPARATOR);

  // disclosures may be empty
  // but the separator before the key binding jwt must exist
  if (separated.length < 2) {
    throw new SDJWTInvalidFormatError('Not a valid SD-JWT');
  }

  const jwt = separated.shift();
  const keyBindingJWT = separated.pop();

  return {
    jwt: jwt,
    disclosures: separated,
    keyBindingJWT: keyBindingJWT,
  };
};

/**
 * Splits the compact SD-JWT into parts based on the FORMAT_SEPARATOR
 *
 * @param sdJWT Compact SD-JWT with appended disclosures and key binding JWT
 * @returns jwt input payload, an array of disclosures and a compact key binding jwt if present
 */
export const decodeSDJWT: DecodeSDJWT = (sdJWT) => {
  const { jwt, disclosures, keyBindingJWT } = splitSDJWT(sdJWT);

  const { payload: unverifiedInputSDJWT, header } = decodeJWT(jwt);

  return {
    header,
    unverifiedInputSDJWT,
    disclosures: decodeDisclosures(disclosures),
    keyBindingJWT: keyBindingJWT,
  };
};

/**
 * Replaces _sd digests present in the SD-JWT with disclosed claims
 *
 * @param sdJWT SD-JWT
 * @param disclosures Array of Disclosure
 * @returns sd-jwt with all disclosed claims
 */
export const unpackSDJWT: UnpackSDJWT = async (sdjwt, disclosures, getHasher) => {
  const hashAlg = (sdjwt[SD_HASH_ALG] as string) || DEFAULT_SD_HASH_ALG;
  const hasher = await getHasher(hashAlg);
  const map = createHashMapping(disclosures, hasher);

  const { _sd_alg, ...payload } = sdjwt;
  return unpack({ obj: payload, map });
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
  if (!isObject(disclosureFrame)) {
    throw new PackSDJWTError('DisclosureFrame must be an object');
  }

  if (!disclosureFrame) {
    throw new PackSDJWTError('no disclosureFrame found');
  }

  if (!hasher || typeof hasher !== 'function') {
    throw new PackSDJWTError('Hasher is required and must be a function');
  }

  if (!claims || typeof claims !== 'object') {
    throw new PackSDJWTError('no claims found');
  }

  const sd = disclosureFrame[SD_DIGEST];

  let packedClaims;
  let disclosures: any[] = [];

  if (claims instanceof Array) {
    packedClaims = [];
    const recursivelyPackedClaims = {};

    for (const key in disclosureFrame) {
      if (key !== SD_DIGEST && key !== SD_DECOY_COUNT) {
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

    const decoys = createDecoy(disclosureFrame[SD_DECOY_COUNT], hasher, options?.generateSalt);
    decoys.forEach((decoy) => {
      packedClaims.push({ '...': decoy });
    });
  } else {
    packedClaims = {};
    const recursivelyPackedClaims = {};
    for (const key in disclosureFrame) {
      if (key !== SD_DIGEST && key !== SD_DECOY_COUNT) {
        const packed = await packSDJWT(claims[key], disclosureFrame[key] as DisclosureFrame, hasher, options);
        recursivelyPackedClaims[key] = packed.claims;
        disclosures = disclosures.concat(packed.disclosures);
      }
    }

    const _sd: string[] = [];

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

    const decoys = createDecoy(disclosureFrame[SD_DECOY_COUNT], hasher, options?.generateSalt);
    decoys.forEach((decoy) => {
      _sd.push(decoy);
    });

    if (_sd.length > 0) {
      packedClaims[SD_DIGEST] = _sd.sort();
    }
  }
  return { claims: packedClaims, disclosures };
};
