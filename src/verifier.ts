import { importJWK, jwtVerify } from 'jose';
import { decodeSDJWT, unpackSDJWT } from './common.js';
import { FORMAT_SEPARATOR, KB_JWT_TYPE_HEADER } from './constants.js';
import { VerifySDJWT } from './types.js';

/**
 * Verifies base64 encoded SD JWT against issuer's public key
 * optional verification of aud and nonce
 *
 * @param sdJWT base64 url encoded SD JWT
 * @param getIssuerKey callback to get the sd-jwt issuer's public key
 * @param expected_aud
 * @param expected_nonce
 * @returns decoded SD-JWT with any disclosed claims
 */
export const verifySDJWT: VerifySDJWT = async (sdJWT, { getIssuerKey, expected_aud, expected_nonce }) => {
  const { unverifiedInputSdJwt: jwt, disclosures, keyBindingJWT } = decodeSDJWT(sdJWT);

  if (expected_aud || expected_nonce) {
    const holderPublicKey = jwt.cnf?.jwk;
    if (!holderPublicKey) {
      throw new Error('No holder public key in SD-JWT');
    }
    let kbJwt;
    try {
      const holderJWK = await importJWK(holderPublicKey, 'ES256');
      kbJwt = await jwtVerify(keyBindingJWT, holderJWK);
    } catch (e) {
      throw new Error('Failed to verify KB_JWT');
    }

    if (kbJwt.protectedHeader.typ !== KB_JWT_TYPE_HEADER) {
      throw new Error('Invalid KB_JWT header type');
    }

    if (kbJwt.payload.aud !== expected_aud) {
      throw new Error('Invalid KB_JWT aud');
    }

    if (kbJwt.payload.nonce !== expected_nonce) {
      throw new Error('Invalid KB_JWT nonce');
    }
  }

  const jwtPayload = sdJWT.split(FORMAT_SEPARATOR)[0];
  const key = await getIssuerKey(jwt.iss);

  try {
    await jwtVerify(jwtPayload, key);
  } catch (e) {
    throw new Error('Failed to verify SD-JWT');
  }

  return unpackSDJWT(jwt, disclosures);
};
