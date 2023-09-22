import { JWTHeaderParameters, SignJWT } from 'jose';
import { packSDJWT } from './common.js';
import { FORMAT_SEPARATOR, SD_JWT_TYPE } from './constants.js';
import { IssueSDJWT } from './types.js';

export const issueSDJWT: IssueSDJWT = async ({
  header,
  payload,
  disclosureFrame,
  alg,
  getHasher,
  hash_alg = 'sha-256',
  generateSalt,
  getIssuerPrivateKey,
  holderPublicKey,
}) => {
  const hasher = await getHasher(hash_alg);
  const issuerPrivateKey = await getIssuerPrivateKey();

  const { claims, disclosures } = await packSDJWT(payload, disclosureFrame, hasher, { generateSalt });

  const protectedHeader: JWTHeaderParameters = {
    typ: SD_JWT_TYPE,
    alg,
    ...header,
  };

  if (holderPublicKey) {
    claims.cnf = {
      jwk: holderPublicKey,
    };
  }

  const jwt = await new SignJWT(claims).setProtectedHeader(protectedHeader).sign(issuerPrivateKey);

  let combined = jwt;
  if (disclosures.length > 0) {
    combined += FORMAT_SEPARATOR + disclosures.join(FORMAT_SEPARATOR);
  }
  combined += FORMAT_SEPARATOR; // kb_jwt separator
  return combined;
};
