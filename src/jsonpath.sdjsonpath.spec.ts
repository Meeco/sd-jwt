import crypto from 'crypto';

import { splitSDJWT } from './common.js';
import { base64encode, decodeJWT } from './helpers.js';

import { SDJsonpath } from './jsonpath.js';
import { COMPLEX_SD_JWT, COMPLEX_SD_JWT_DISCLOSURE_JSONPATHS } from './test-utils/index.js';
import { GetHasher } from './types.js';

const hasher = (data) => {
  const digest = crypto.createHash('sha256').update(data).digest();
  return base64encode(digest);
};

const getHasher: GetHasher = () => Promise.resolve(hasher);

describe('#SDJsonpath', () => {
  it('#fromJWT', () => {
    const { jwt, disclosures, keyBindingJWT: _kbjwt } = splitSDJWT(COMPLEX_SD_JWT);
    const { payload } = decodeJWT(jwt);

    const jsonpaths = SDJsonpath.fromJWT(payload, disclosures, hasher);

    expect(jsonpaths).toEqual(COMPLEX_SD_JWT_DISCLOSURE_JSONPATHS);
  });

  it('#fromCompactJWT', async () => {
    const jsonpaths = await SDJsonpath.fromCompactJWT(COMPLEX_SD_JWT, getHasher);

    expect(jsonpaths).toEqual(COMPLEX_SD_JWT_DISCLOSURE_JSONPATHS);
  });

  it('#getJWT', async () => {
    const selectedClaims = [
      '$.msisdn',
      '$.verified_claims.verification.evidence[0].time',
      '$.verified_claims.verification.evidence[0].document',
    ];

    const jwtWithSelectedClaims = await SDJsonpath.getJWT(COMPLEX_SD_JWT, selectedClaims, getHasher);

    const { jwt: originalJwt } = splitSDJWT(COMPLEX_SD_JWT);

    const { jwt, disclosures } = splitSDJWT(jwtWithSelectedClaims);

    expect(jwt).toEqual(originalJwt);

    expect(disclosures).toEqual([
      'WyJDOUdTb3VqdmlKcXVFZ1lmb2pDYjFBIiwgIm1zaXNkbiIsICI0OTEyMzQ1Njc4OSJd',
      'WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInRpbWUiLCAiMjAxMi0wNC0yMlQxMTozMFoiXQ',
      'WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImRvY3VtZW50IiwgeyJ0eXBlIjogImlkY2FyZCIsICJpc3N1ZXIiOiB7Im5hbWUiOiAiU3RhZHQgQXVnc2J1cmciLCAiY291bnRyeSI6ICJERSJ9LCAibnVtYmVyIjogIjUzNTU0NTU0IiwgImRhdGVfb2ZfaXNzdWFuY2UiOiAiMjAxMC0wMy0yMyIsICJkYXRlX29mX2V4cGlyeSI6ICIyMDIwLTAzLTIyIn1d',
    ]);
  });
});
