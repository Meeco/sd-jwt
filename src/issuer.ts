import { packSDJWT } from './common.js';
import { SD_HASH_ALG, SD_JWT_TYPE } from './constants.js';
import { IssueSDJWT } from './types.js';
import { base64encode, combineSDJWT } from './helpers.js';
import { IssueSDJWTError } from './errors.js';

/**
 * Issues a new Selectively Disclosable JWT (SD-JWT).
 *
 * Packs the provided payload based on the disclosureFrame,
 * adds the `_sd_alg` claim (derived from the `hash.alg` option) to indicate
 * the hashing algorithm used for disclosures.
 * @param header The JWT header object.
 * @param payload The JWT payload object containing the claims.
 * @param disclosureFrame An object defining which claims in the payload should be made selectively disclosable.
 * @param options Options for issuing the SD-JWT.
 * @param options.signer An asynchronous function that takes the protected header and payload, and returns the signature.
 * @param options.hash An object containing the hash algorithm information.
 * @param options.hash.alg A string representing the hash algorithm used for disclosures (e.g., "sha-256"). This will be added as the _sd_alg claim.
 * @param options.hash.callback An asynchronous function that takes data and returns its hash.
 * @param options.generateSalt An optional function to generate a salt for disclosures. If not provided, a default salt generator will be used.
 * @param options.cnf An optional object representing the confirmation method claim (e.g., for key binding).
 * @returns A Promise that resolves to the compact representation of the SD-JWT (a string).
 * @throws {IssueSDJWTError} If the signer or hasher callback is missing or not a function.
 *  */
export const issueSDJWT: IssueSDJWT = async (header, payload, disclosureFrame, { signer, hash, generateSalt, cnf }) => {
  if (!signer || typeof signer !== 'function') {
    throw new IssueSDJWTError('Signer function is required');
  }
  if (!hash?.callback || typeof hash.callback !== 'function') {
    throw new IssueSDJWTError('Hasher callback is required');
  }

  const { claims, disclosures } = await packSDJWT(payload, disclosureFrame, hash.callback, { generateSalt });

  const protectedHeader = {
    typ: SD_JWT_TYPE,
    ...header,
  };

  if (cnf) {
    claims.cnf = cnf;
  }

  claims[SD_HASH_ALG] = hash.alg;

  const signature = await signer(protectedHeader, claims);

  const jwt: string = [
    base64encode(JSON.stringify(protectedHeader)),
    base64encode(JSON.stringify(claims)),
    signature,
  ].join('.');

  return combineSDJWT(jwt, disclosures);
};
