import { decodeSDJWT, unpackSDJWT } from './common.js';
import { FORMAT_SEPARATOR, KB_JWT_TYPE_HEADER } from './constants.js';
import { VerifySDJWTError } from './errors.js';
import { decodeJWT } from './helpers.js';
import { VerifySDJWT } from './types.js';

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

  const hasher = await getHasher('sha-256');

  if (!hasher || typeof hasher !== 'function') {
    throw new VerifySDJWTError('GetHasher must return a function');
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

  return unpackSDJWT(jwt, disclosures, getHasher);
};
