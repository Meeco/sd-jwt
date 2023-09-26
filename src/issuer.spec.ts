import crypto from 'crypto';
import { SignJWT, importJWK } from 'jose';
import { base64encode } from './helpers';
import { issueSDJWT } from './issuer';
import { ISSUER_KEYPAIR } from './test-utils/params';

describe('issueSDJWT', () => {
  const hasher = (data) => {
    const digest = crypto.createHash('sha256').update(data).digest();
    return base64encode(digest);
  };

  const generateSalt = () => 'salt';

  it('should be able to issue a signed compact SD-JWT', async () => {
    const signer = async (header, payload) => {
      const issuerPrivateKey = await importJWK(ISSUER_KEYPAIR.PRIVATE_KEY_JWK, header.alg);
      return new SignJWT(payload).setProtectedHeader(header).sign(issuerPrivateKey);
    };

    const payload = {
      id: 123,
      items: [[1, 2], 3],
    };

    const disclosureFrame = {
      _sd: ['id', 'items'],
    };

    const result = await issueSDJWT({ alg: 'ES256' }, payload, disclosureFrame, {
      hash: {
        alg: 'sha-256',
        callback: hasher,
      },
      signer,
      generateSalt,
    });

    const expectedHeader = 'eyJ0eXAiOiJzZCtqd3QiLCJhbGciOiJFUzI1NiJ9';
    const expectedPayload =
      'eyJfc2QiOlsia2pBSTRzV3JoV1R3ZHBTWmZMWlBhcFhFZVdyRksyZHVBUUhCbl83NloyayIsIjdqcF82Tk5VQTRIRTJDWlJSMmZ0b2g0Wm9TcG5ZaG0tNmtvUE0tbzhRX2ciXX0';

    const { 0: jwtHeader, 1: jwtPayload } = result.split('.');
    expect(jwtHeader).toEqual(expectedHeader);
    expect(jwtPayload).toEqual(expectedPayload);
  });
});
