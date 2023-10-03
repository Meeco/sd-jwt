import { packSDJWT } from './common.js';
import { SD_JWT_TYPE } from './constants.js';
import { IssueSDJWT } from './types.js';
import { base64encode, combineSDJWT } from './helpers.js';
import { IssueSDJWTError } from './errors.js';

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

  const signature = await signer(protectedHeader, claims);

  const jwt: string = [
    base64encode(JSON.stringify(protectedHeader)),
    base64encode(JSON.stringify(claims)),
    signature,
  ].join('.');

  return combineSDJWT(jwt, disclosures);
};
