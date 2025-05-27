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
 *
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
