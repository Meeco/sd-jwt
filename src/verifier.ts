import { decodeSDJWT, unpackSDJWT } from './common.js';
import { DEFAULT_SD_HASH_ALG, FORMAT_SEPARATOR, KB_JWT_TYPE_HEADER, SD_HASH_ALG } from './constants.js';
import { VerifySDJWTError } from './errors.js';
import { decodeJWT, resolveHasher } from './helpers.js';
import { SDJWTPayload, VerifySDJWT } from './types.js';

/**
 * Verifies base64 encoded SD JWT against issuer's public key
 * optional verification of aud and nonce
 *
 * @param sdJWT Compact SD-JWT
 * @param verifier Configurable Verifier function
 * @param opts Optional keybinding verifier
 * @returns SD-JWT with any disclosed claims
 */
export const verifySDJWT: VerifySDJWT = async (sdjwt, verifier, getHasher, opts) => {
  if (typeof sdjwt !== 'string') {
    throw new VerifySDJWTError('Invalid SD-JWT input - expects a compact SD-JWT as string');
  }

  if (!verifier || typeof verifier !== 'function') {
    throw new VerifySDJWTError('Verifier function is required');
  }

  if (!getHasher || typeof getHasher !== 'function') {
    throw new VerifySDJWTError('GetHasher function is requred');
  }

  const { unverifiedInputSDJWT: jwt, disclosures, keyBindingJWT } = decodeSDJWT(sdjwt);

  const kb = opts?.kb;

  if (keyBindingJWT && !kb?.verifier) {
    throw new VerifySDJWTError('Key Binding JWT found but no KB JWT verifier function was provided');
  }

  if (kb) {
    const holderPublicKey = jwt.cnf?.jwk;

    if (!holderPublicKey) {
      throw new VerifySDJWTError('No holder public key in SD-JWT');
    }

    if (kb.verifier) {
      if (typeof kb.verifier !== 'function') {
        throw new VerifySDJWTError('Invalid KB_JWT verifier function');
      }

      if (!keyBindingJWT) {
        throw new VerifySDJWTError('No Key Binding JWT found');
      }

      const { typ } = decodeJWT(keyBindingJWT).header;
      if (typ !== KB_JWT_TYPE_HEADER) {
        throw new VerifySDJWTError(`Invalid Key Binding JWT: expected typ '${KB_JWT_TYPE_HEADER}', received '${typ}'`);
      }

      try {
        const verifiedKBJWT = await kb.verifier(keyBindingJWT, holderPublicKey);
        if (!verifiedKBJWT) {
          throw new VerifySDJWTError('KB JWT is invalid');
        }
      } catch (_e) {
        throw new VerifySDJWTError('Failed to verify Key Binding JWT');
      }

      const presentationWithoutKBJWT = sdjwt.slice(0, sdjwt.lastIndexOf(FORMAT_SEPARATOR) + 1);
      const sdHashAlg = (jwt[SD_HASH_ALG] as string) || DEFAULT_SD_HASH_ALG;
      const sdHasher = await resolveHasher(getHasher, sdHashAlg);

      const signedSdHash = decodeJWT(keyBindingJWT).payload.sd_hash;
      const presentedSdHash = sdHasher(presentationWithoutKBJWT);

      if (signedSdHash !== presentedSdHash) {
        throw new VerifySDJWTError('Key Binding JWT sd_hash does not match the presented SD-JWT');
      }
    }
  }

  const compactJWT = sdjwt.split(FORMAT_SEPARATOR)[0];

  try {
    const verified = await verifier(compactJWT);
    if (!verified) {
      throw new VerifySDJWTError('Failed to verify SD-JWT');
    }
  } catch (_e) {
    throw new VerifySDJWTError('Failed to verify SD-JWT');
  }

  if (!opts?.time?.skip) {
    assertWithinValidityPeriod(jwt, opts?.time?.skewSeconds ?? 0);
  }

  return unpackSDJWT(jwt, disclosures, getHasher);
};

const assertWithinValidityPeriod = (payload: SDJWTPayload, skewSeconds: number) => {
  const now = Math.floor(Date.now() / 1000);

  if (typeof payload.exp === 'number' && payload.exp <= now - skewSeconds) {
    throw new VerifySDJWTError(`SD-JWT expired at ${payload.exp}`);
  }

  if (typeof payload.nbf === 'number' && payload.nbf > now + skewSeconds) {
    throw new VerifySDJWTError(`SD-JWT is not valid before ${payload.nbf}`);
  }
};
