import { decodeSDJWT, unpackSDJWT } from './common';
import { FORMAT_SEPARATOR, KB_JWT_TYPE_HEADER } from './constants';
import { VerifySDJWT } from './types';
import { decodeJWT } from './helpers';

/**
 * Verifies base64 encoded SD JWT against issuer's public key
 * optional verification of aud and nonce
 *
 * @param sdJWT Compact SD-JWT
 * @param verifier Configurable Verifier function
 * @param opts Optional keybinding verifier
 * @returns SD-JWT with any disclosed claims
 */
export const verifySDJWT: VerifySDJWT = async (sdjwt, verifier, opts) => {
  if (typeof sdjwt !== 'string') {
    throw new Error('Invalid SD-JWT input - expects a compact SD-JWT as string');
  }

  if (!verifier && typeof verifier !== 'function') {
    throw new Error('Verifier function is required');
  }

  const { unverifiedInputSdJwt: jwt, disclosures, keyBindingJWT } = decodeSDJWT(sdjwt);

  if (opts && opts.kb) {
    const kb = opts.kb;
    const holderPublicKey = jwt.cnf?.jwk;
    if (!holderPublicKey) {
      throw new Error('No holder public key in SD-JWT');
    }

    if (!kb.skipCheck) {
      if (!keyBindingJWT) {
        throw new Error('No Key Binding JWT found');
      }

      const kbjwt = decodeJWT(keyBindingJWT);
      if (kbjwt.header.typ !== KB_JWT_TYPE_HEADER) {
        throw new Error('KB_JWT error: invalid header type');
      }
      if (!kbjwt.payload.aud) {
        throw new Error('KB_JWT error: aud not found');
      }
      if (!kbjwt.payload.nonce) {
        throw new Error('KB_JWT error: nonce not found');
      }
    }

    if (kb.verifier) {
      if (typeof kb.verifier !== 'function') {
        throw new Error('Invalid KB_JWT verifier function');
      }
      try {
        const verifiedKBJWT = await kb.verifier(keyBindingJWT, holderPublicKey);
        if (!verifiedKBJWT) {
          throw new Error('KB JWT is invalid');
        }
      } catch (e) {
        throw new Error('Failed to verify Key Binding JWT');
      }
    }
  }

  const compactJWT = sdjwt.split(FORMAT_SEPARATOR)[0];

  try {
    const verified = await verifier(compactJWT);
    if (!verified) {
      throw new Error('Failed to verify SD-JWT');
    }
  } catch (e) {
    throw new Error('Failed to verify SD-JWT');
  }

  return unpackSDJWT(jwt, disclosures);
};
