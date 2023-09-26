import * as crypto from 'crypto';
import { base64encode } from './helpers';
import { ISSUER_KEYPAIR } from './test-utils/params';
import { issueSDJWT } from './issuer';
import { importJWK } from 'jose';

describe('issueSDJWT', () => {
  const hasher = (data) => {
    const digest = crypto.createHash('sha256').update(data).digest();
    const hash = base64encode(digest);
    return Promise.resolve(hash);
  };

  const generateSalt = () => 'salt';

  it('should be able to issue a signed compact SD-JWT', async () => {
    const alg = 'ES256';
    const getHasher = () => Promise.resolve(hasher);
    const getIssuerPrivateKey = () => importJWK(ISSUER_KEYPAIR.PRIVATE_KEY_JWK, alg);

    const payload = {
      id: 123,
      items: [[1, 2], 3],
    };

    const disclosureFrame = {
      _sd: ['id', 'items'],
    };

    const result = await issueSDJWT({
      alg,
      payload,
      disclosureFrame,
      generateSalt,
      getIssuerPrivateKey,
      getHasher,
      hash_alg: 'sha-256',
    });

    const expectedHeader = 'eyJ0eXAiOiJzZCtqd3QiLCJhbGciOiJFUzI1NiJ9';
    const expectedPayload =
      'eyJfc2QiOlsia2pBSTRzV3JoV1R3ZHBTWmZMWlBhcFhFZVdyRksyZHVBUUhCbl83NloyayIsIjdqcF82Tk5VQTRIRTJDWlJSMmZ0b2g0Wm9TcG5ZaG0tNmtvUE0tbzhRX2ciXX0';

    const jwt = result.split('.');
    expect(jwt[0]).toEqual(expectedHeader);
    expect(jwt[1]).toEqual(expectedPayload);
  });
});
