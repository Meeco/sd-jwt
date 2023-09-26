import { packSDJWT } from './common';
import { FORMAT_SEPARATOR, SD_JWT_TYPE } from './constants';
import { IssueSDJWT } from './types';
import { base64encode } from './helpers';

export const issueSDJWT: IssueSDJWT = async (header, payload, disclosureFrame, { signer, hash, generateSalt, cnf }) => {
  if (!signer || typeof signer !== 'function') {
    throw new Error('Signer function is required');
  }
  if (!hash?.callback || typeof hash.callback !== 'function') {
    throw new Error('Hasher callback is required');
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

  let combined = jwt;
  if (disclosures.length > 0) {
    combined += FORMAT_SEPARATOR + disclosures.join(FORMAT_SEPARATOR);
  }
  combined += FORMAT_SEPARATOR; // kb_jwt separator
  return combined;
};
