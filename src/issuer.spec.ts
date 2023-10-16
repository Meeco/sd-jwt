import crypto from 'crypto';
import { SignJWT, importJWK } from 'jose';
import { base64encode, decodeJWT } from './helpers';
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
      return (await new SignJWT(payload).setProtectedHeader(header).sign(issuerPrivateKey)).split('.').pop();
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

    const jwtHeader = result.split('.')[0];
    const { payload: issuedPayload } = decodeJWT(result);

    const expectedHeader = 'eyJ0eXAiOiJzZCtqd3QiLCJhbGciOiJFUzI1NiJ9';
    const expectedPayload = [
      '7jp_6NNUA4HE2CZRR2ftoh4ZoSpnYhm-6koPM-o8Q_g',
      'kjAI4sWrhWTwdpSZfLZPapXEeWrFK2duAQHBn_76Z2k',
    ];

    expect(jwtHeader).toEqual(expectedHeader);
    expect(issuedPayload._sd).toEqual(expect.arrayContaining(expectedPayload));
  });
});
