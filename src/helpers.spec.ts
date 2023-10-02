import { base64decode, base64encode } from './helpers';

const disclosure: string[] = ['5a2W0_NrlEZzfqmk_7Pq-w', 'administeringCentre', 'Praxis Sommergarten'];
const encodedDisclosure: string =
  'WyI1YTJXMF9OcmxFWnpmcW1rXzdQcS13IiwiYWRtaW5pc3RlcmluZ0NlbnRyZSIsIlByYXhpcyBTb21tZXJnYXJ0ZW4iXQ';

describe('base64encode', () => {
  it('should encode a disclosureArray string', () => {
    const disclosureArray = JSON.stringify(disclosure);
    const encoded = base64encode(disclosureArray);
    expect(encoded).toEqual(encodedDisclosure);
  });
});

describe('base64decode', () => {
  it('should decode a base64url encoded string', () => {
    const decoded = base64decode(encodedDisclosure);
    expect(JSON.parse(decoded)).toEqual(disclosure);
  });
});
