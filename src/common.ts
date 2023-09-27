import { DEFAULT_SD_HASH_ALG, FORMAT_SEPARATOR, SD_DIGEST, SD_HASH_ALG } from './constants.js';
import { DecodeSDJWT, DisclosureFrame, PackSDJWT, UnpackSDJWT } from './types.js';
import { createDisclosure, createHashMapping, decodeDisclosure, unpack, decodeJWT } from './helpers.js';

/**
 * Splits the compact SD-JWT into parts based on the FORMAT_SEPARATOR
 *
 * @param sdJWT Compact SD-JWT with appended disclosures and key binding JWT
 * @returns jwt input payload, an array of disclosures and a compact key binding jwt if present
 */
export const decodeSDJWT: DecodeSDJWT = (sdJWT) => {
  const s = sdJWT.split(FORMAT_SEPARATOR);

  // disclosures may be empty
  // but the separator before the key binding jwt must exist
  if (s.length < 2) {
    throw Error('Not a valid SD-JWT');
  }
  const { payload: unverifiedInputSdJwt } = decodeJWT(s.shift() || '');
  const keyBindingJWT = s.pop();
  const disclosures = decodeDisclosure(s);

  return {
    unverifiedInputSdJwt,
    disclosures,
    keyBindingJWT,
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
  // TODO: check for correct object type for disclosureFrame
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
