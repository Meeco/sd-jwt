import crypto from 'crypto';
import { base64encode } from './helpers';
import { GetHasher, Hasher, Signer, Verifier } from './types';
import { issueSDJWT } from './issuer';
import { verifySDJWT } from './verifier';
import { getTestCases, loadClaims, loadDisclosureFrame } from './test-utils/helpers';

const alg = 'sha-256';
const hasher: Hasher = (data) => {
  const digest = crypto.createHash('sha256').update(data).digest();
  return base64encode(digest);
};
const getHasher: GetHasher = () => {
  return Promise.resolve(hasher);
};
const signer: Signer = () => Promise.resolve('signed');
const verifier: Verifier = () => Promise.resolve(true);

const testCases = getTestCases();

it.each(testCases)('should be able to issue then verify %s claims', async (testCase) => {
  const claims = await loadClaims(testCase);
  const disclosureFrame = await loadDisclosureFrame(testCase);

  const header = { alg: 'ES256' };

  const sdjwt = await issueSDJWT(header, claims, disclosureFrame, {
    hash: {
      alg,
      callback: hasher,
    },
    signer,
  });

  const result = await verifySDJWT(sdjwt, verifier, getHasher);

  expect(result).toEqual(claims);
});
