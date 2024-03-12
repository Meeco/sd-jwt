import { Disclosure } from 'src/types.js';

export const mockStringDisclosure: Disclosure = {
  disclosure: 'mocked-string-disclosure',
  key: 'stringClaim',
  value: 'selectively-disclosed-claim',
};

export const mockNumberDisclosure: Disclosure = {
  disclosure: 'mocked-number-disclosure',
  key: 'numberClaim',
  value: 1,
};

export const mockBooleanDisclosure: Disclosure = {
  disclosure: 'mocked-number-disclosure',
  key: 'booleanClaim',
  value: 1,
};

export const mockObjectDisclosure: Disclosure = {
  disclosure: 'mocked-number-disclosure',
  key: 'objClaim',
  value: { claim: 'test' },
};

export const mockArrayItem: Disclosure = {
  disclosure: 'mocked-base64encoded-disclosure',
  key: null,
  value: 'selectively-disclosed-array-item',
};

export const buildMockArrayItem = (props) => {
  return {
    ...mockArrayItem,
    ...props,
  };
};
