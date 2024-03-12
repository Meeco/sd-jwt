import { DigestMap, SDJWTDisclosureStruct } from './jsonpath.js';
import {
  buildMockArrayItem,
  mockArrayItem,
  mockBooleanDisclosure,
  mockNumberDisclosure,
  mockObjectDisclosure,
  mockStringDisclosure,
} from './test-utils/index.js';
import { Disclosure } from './types.js';

describe('#SDJWTDisclosureStruct', () => {
  describe('listDisclosureJsonPaths', () => {
    describe('Selectively Disclosable Claims', () => {
      it('single claim', () => {
        const sdjwt = {
          _sd: ['sd-hash-1', 'decoy-sd-hash'],
        };

        const digestMap: DigestMap = new Map([['sd-hash-1', mockStringDisclosure]]);

        const disclosures = new SDJWTDisclosureStruct({ jwt: sdjwt, digestMap }).listDisclosureJsonPaths();

        expect(disclosures).toEqual({
          '$.stringClaim': mockStringDisclosure.value,
        });
      });

      it('multiple claims', () => {
        const sdjwt = {
          _sd: ['sd-hash-1', 'sd-hash-2', 'sd-hash-3', 'sd-hash-4', 'decoy-sd-hash'],
        };

        const digestMap: DigestMap = new Map([
          ['sd-hash-1', mockStringDisclosure],
          ['sd-hash-2', mockNumberDisclosure],
          ['sd-hash-3', mockObjectDisclosure],
          ['sd-hash-4', mockBooleanDisclosure],
        ]);

        const disclosures = new SDJWTDisclosureStruct({ jwt: sdjwt, digestMap }).listDisclosureJsonPaths();

        expect(disclosures).toEqual({
          '$.stringClaim': mockStringDisclosure.value,
          '$.numberClaim': mockNumberDisclosure.value,
          '$.objClaim': mockObjectDisclosure.value,
          '$.booleanClaim': mockBooleanDisclosure.value,
        });
      });

      it('array item', () => {
        const sdjwt = {
          claim: [{ '...': 'sd-hash' }, { '...': 'decoy-sd-hash' }, 'always-visible-value'],
        };

        const digestMap: DigestMap = new Map([['sd-hash', mockArrayItem]]);

        const disclosures = new SDJWTDisclosureStruct({ jwt: sdjwt, digestMap }).listDisclosureJsonPaths();

        expect(disclosures).toEqual({
          '$.claim[0]': mockArrayItem.value,
        });
      });

      it('multiple array claims in array', () => {
        const sdjwt = {
          claim: [
            { '...': 'sd-hash-1' },
            { '...': 'decoy-sd-hash' },
            { '...': 'sd-hash-2' },
            'always-visible-value',
            { '...': 'sd-hash-3' },
            { '...': 'sd-hash-4' },
          ],
        };

        const digestMap: DigestMap = new Map([
          ['sd-hash-1', mockArrayItem],
          ['sd-hash-2', mockArrayItem],
          ['sd-hash-3', mockArrayItem],
          ['sd-hash-4', mockArrayItem],
        ]);

        const disclosures = new SDJWTDisclosureStruct({ jwt: sdjwt, digestMap }).listDisclosureJsonPaths();

        expect(disclosures).toEqual({
          '$.claim[0]': mockArrayItem.value,
          '$.claim[2]': mockArrayItem.value,
          '$.claim[4]': mockArrayItem.value,
          '$.claim[5]': mockArrayItem.value,
        });
      });

      it('single claim + array item', () => {
        const sdjwt = {
          _sd: ['sd-hash-1', 'decoy-sd-hash'],
          arrayClaim: [{ '...': 'sd-hash-2' }, { '...': 'decoy-sd-hash' }, 'always-visible-value'],
        };

        const digestMap: DigestMap = new Map([
          ['sd-hash-1', mockStringDisclosure],
          ['sd-hash-2', mockArrayItem],
        ]);

        const disclosures = new SDJWTDisclosureStruct({ jwt: sdjwt, digestMap }).listDisclosureJsonPaths();

        expect(disclosures).toEqual({
          '$.stringClaim': mockStringDisclosure.value,
          '$.arrayClaim[0]': mockArrayItem.value,
        });
      });
    });

    describe('Nested Selectively Disclosable Claims', () => {
      it('single nested claim', () => {
        const sdjwt = {
          parent: {
            _sd: ['sd-hash-1', 'decoy-sd-hash'],
          },
        };

        const digestMap: DigestMap = new Map([['sd-hash-1', mockStringDisclosure]]);

        const disclosures = new SDJWTDisclosureStruct({ jwt: sdjwt, digestMap }).listDisclosureJsonPaths();

        expect(disclosures).toEqual({
          '$.parent.stringClaim': mockStringDisclosure.value,
        });
      });

      it('multiple nested claim', () => {
        const sdjwt = {
          parent: {
            _sd: ['sd-hash-1', 'decoy-sd-hash'],
            child: { child: { child: { _sd: ['sd-hash-2'] } } },
          },
        };

        const digestMap: DigestMap = new Map([
          ['sd-hash-1', mockStringDisclosure],
          ['sd-hash-2', mockBooleanDisclosure],
        ]);

        const disclosures = new SDJWTDisclosureStruct({ jwt: sdjwt, digestMap }).listDisclosureJsonPaths();

        expect(disclosures).toEqual({
          '$.parent.stringClaim': mockStringDisclosure.value,
          '$.parent.child.child.child.booleanClaim': mockBooleanDisclosure.value,
        });
      });

      it('claim in array item', () => {
        const sdjwt = {
          parent: {
            claim: [{ _sd: ['sd-hash-1', 'decoy-sd-hash'] }, { '...': 'sd-hash-2' }],
          },
        };

        const digestMap: DigestMap = new Map([
          ['sd-hash-1', mockStringDisclosure],
          ['sd-hash-2', mockArrayItem],
        ]);

        const disclosures = new SDJWTDisclosureStruct({ jwt: sdjwt, digestMap }).listDisclosureJsonPaths();

        expect(disclosures).toEqual({
          '$.parent.claim[0].stringClaim': mockStringDisclosure.value,
          '$.parent.claim[1]': mockArrayItem.value,
        });
      });

      it('array in array', () => {
        const sdjwt = {
          parent: {
            claim: [[{ _sd: ['sd-hash-1', 'decoy-sd-hash'] }, [1, [{ '...': 'sd-hash-2' }]]]],
          },
        };

        const digestMap: DigestMap = new Map([
          ['sd-hash-1', mockStringDisclosure],
          ['sd-hash-2', mockArrayItem],
        ]);

        const disclosures = new SDJWTDisclosureStruct({ jwt: sdjwt, digestMap }).listDisclosureJsonPaths();

        expect(disclosures).toEqual({
          '$.parent.claim[0][0].stringClaim': mockStringDisclosure.value,
          '$.parent.claim[0][1][1][0]': mockArrayItem.value,
        });
      });
    });

    describe('Recursive Selectively Disclosable Claims', () => {
      it('object in object', () => {
        const mockRecursiveDisclosure: Disclosure = {
          disclosure: 'mocked-recursive-disclosure',
          key: 'recursive',
          value: {
            _sd: ['sd-hash-2'],
          },
        };

        const sdjwt = {
          _sd: ['sd-hash-1'],
        };

        const digestMap: DigestMap = new Map([
          ['sd-hash-1', mockRecursiveDisclosure],
          ['sd-hash-2', mockStringDisclosure],
        ]);

        const disclosures = new SDJWTDisclosureStruct({ jwt: sdjwt, digestMap }).listDisclosureJsonPaths();

        expect(disclosures).toEqual({
          '$.recursive': mockRecursiveDisclosure.value,
          '$.recursive.stringClaim': mockStringDisclosure.value,
        });
      });

      it('object in array', () => {
        const mockRecursiveDisclosure: Disclosure = {
          disclosure: 'mocked-recursive-disclosure',
          key: null,
          value: {
            _sd: ['sd-hash-2'],
          },
        };

        const sdjwt = {
          claim: [{ '...': 'sd-hash-1' }],
        };

        const digestMap: DigestMap = new Map([
          ['sd-hash-1', mockRecursiveDisclosure],
          ['sd-hash-2', mockStringDisclosure],
        ]);

        const disclosures = new SDJWTDisclosureStruct({ jwt: sdjwt, digestMap }).listDisclosureJsonPaths();

        expect(disclosures).toEqual({
          '$.claim[0]': mockRecursiveDisclosure.value,
          '$.claim[0].stringClaim': mockStringDisclosure.value,
        });
      });

      it('array in object', () => {
        const mockRecursiveDisclosure: Disclosure = {
          disclosure: 'mocked-recursive-disclosure',
          key: 'parent',
          value: [{ '...': 'sd-hash-2' }],
        };

        const sdjwt = {
          _sd: ['sd-hash-1'],
        };

        const digestMap: DigestMap = new Map([
          ['sd-hash-1', mockRecursiveDisclosure],
          ['sd-hash-2', mockArrayItem],
        ]);

        const disclosures = new SDJWTDisclosureStruct({ jwt: sdjwt, digestMap }).listDisclosureJsonPaths();

        expect(disclosures).toEqual({
          '$.parent': mockRecursiveDisclosure.value,
          '$.parent[0]': mockArrayItem.value,
        });
      });

      it('array in array', () => {
        const mockRecursiveDisclosure: Disclosure = {
          disclosure: 'mocked-recursive-disclosure',
          key: null,
          value: {
            claim: [{ '...': 'sd-hash-2' }],
          },
        };

        const sdjwt = {
          recursive: [{ '...': 'sd-hash-1' }],
        };

        const digestMap: DigestMap = new Map([
          ['sd-hash-1', mockRecursiveDisclosure],
          ['sd-hash-2', mockArrayItem],
        ]);

        const disclosures = new SDJWTDisclosureStruct({ jwt: sdjwt, digestMap }).listDisclosureJsonPaths();

        expect(disclosures).toEqual({
          '$.recursive[0]': mockRecursiveDisclosure.value,
          '$.recursive[0].claim[0]': mockArrayItem.value,
        });
      });
    });
  });

  describe('getDisclosuresFromJsonpaths', () => {
    describe('simple sdjwt with multiple SD claims', () => {
      const sdjwt = {
        _sd: ['sd-hash-1', 'sd-hash-2', 'sd-hash-3', 'sd-hash-4', 'decoy-sd-hash'],
      };

      const digestMap: DigestMap = new Map([
        ['sd-hash-1', mockStringDisclosure],
        ['sd-hash-2', mockNumberDisclosure],
        ['sd-hash-3', mockObjectDisclosure],
        ['sd-hash-4', mockBooleanDisclosure],
      ]);

      const parser = new SDJWTDisclosureStruct({ jwt: sdjwt, digestMap });

      it('selects one claim', () => {
        const selectedClaims = ['$.stringClaim'];
        const disclosures = parser.getDisclosuresFromJsonpaths(selectedClaims);
        expect(disclosures).toEqual([mockStringDisclosure.disclosure]);
      });

      it('selects multiple claims', () => {
        const selectedClaims = ['$.stringClaim', '$.booleanClaim'];
        const disclosures = parser.getDisclosuresFromJsonpaths(selectedClaims);
        expect(disclosures).toEqual([mockStringDisclosure.disclosure, mockBooleanDisclosure.disclosure]);
      });

      it('throws error when invalid jsonpath claim found', () => {
        const selectedClaims = ['$.invalidClaim'];
        expect(() => parser.getDisclosuresFromJsonpaths(selectedClaims)).toThrow(
          'Cannot find disclosure for provided jsonpath $.invalidClaim',
        );
      });

      it('ignore invalid jsonpath claim with ignoreInvalidJsonpath option', () => {
        const selectedClaims = ['$.invalidClaim'];
        const disclosures = parser.getDisclosuresFromJsonpaths(selectedClaims, { ignoreInvalidJsonpath: true });
        expect(disclosures).toEqual([]);
      });

      it('assumes rootpath if path does not start with $.', () => {
        const selectedClaims = ['stringClaim'];
        const disclosures = parser.getDisclosuresFromJsonpaths(selectedClaims);
        expect(disclosures).toEqual([mockStringDisclosure.disclosure]);
      });
    });

    describe('simple sdjwt with SD array items', () => {
      const sdjwt = {
        claim: [
          { '...': 'sd-hash-1' },
          { '...': 'decoy-sd-hash' },
          { '...': 'sd-hash-2' },
          'always-visible-value',
          { '...': 'sd-hash-3' },
          { '...': 'sd-hash-4' },
        ],
      };

      const digestMap: DigestMap = new Map([
        ['sd-hash-1', buildMockArrayItem({ disclosure: 'mock-array-item-index-0' })],
        ['sd-hash-2', buildMockArrayItem({ disclosure: 'mock-array-item-index-2' })],
        ['sd-hash-3', buildMockArrayItem({ disclosure: 'mock-array-item-index-4' })],
        ['sd-hash-4', buildMockArrayItem({ disclosure: 'mock-array-item-index-5' })],
      ]);

      const parser = new SDJWTDisclosureStruct({ jwt: sdjwt, digestMap });

      it('select one claim', () => {
        const selectedClaims = ['$.claim[4]'];

        const disclosures = parser.getDisclosuresFromJsonpaths(selectedClaims);
        expect(disclosures).toEqual(['mock-array-item-index-4']);
      });

      it('selects multiple claims', () => {
        const selectedClaims = ['$.claim[0]', '$.claim[2]'];

        const disclosures = parser.getDisclosuresFromJsonpaths(selectedClaims);
        expect(disclosures).toEqual(['mock-array-item-index-0', 'mock-array-item-index-2']);
      });
    });

    describe('sdjwt with nested claims', () => {
      const sdjwt = {
        parent: {
          claim: [{ _sd: ['sd-hash-1', 'decoy-sd-hash'] }, { '...': 'sd-hash-2' }],
          child: { child: { child: { _sd: ['sd-hash-3'] } } },
        },
      };

      const digestMap: DigestMap = new Map([
        ['sd-hash-1', mockStringDisclosure],
        ['sd-hash-2', mockArrayItem],
        ['sd-hash-3', mockBooleanDisclosure],
      ]);

      const parser = new SDJWTDisclosureStruct({ jwt: sdjwt, digestMap });

      it('select claims', () => {
        expect(parser.getDisclosuresFromJsonpaths(['$.parent.claim[0].stringClaim'])).toEqual([
          mockStringDisclosure.disclosure,
        ]);

        expect(parser.getDisclosuresFromJsonpaths(['$.parent.claim[1]'])).toEqual([mockArrayItem.disclosure]);

        expect(parser.getDisclosuresFromJsonpaths(['$.parent.child.child.child.booleanClaim'])).toEqual([
          mockBooleanDisclosure.disclosure,
        ]);

        expect(
          parser.getDisclosuresFromJsonpaths([
            '$.parent.claim[0].stringClaim',
            '$.parent.child.child.child.booleanClaim',
            '$.parent.claim[1]',
          ]),
        ).toEqual([mockStringDisclosure.disclosure, mockBooleanDisclosure.disclosure, mockArrayItem.disclosure]);
      });
    });

    describe('sdjwt with recursive claims', () => {
      it('object in object', () => {
        const mockRecursiveDisclosure: Disclosure = {
          disclosure: 'mocked-recursive-disclosure',
          key: 'recursive',
          value: {
            _sd: ['sd-hash-2'],
          },
        };

        const sdjwt = {
          _sd: ['sd-hash-1'],
        };

        const digestMap: DigestMap = new Map([
          ['sd-hash-1', mockRecursiveDisclosure],
          ['sd-hash-2', mockStringDisclosure],
        ]);

        const parser = new SDJWTDisclosureStruct({ jwt: sdjwt, digestMap });

        expect(parser.getDisclosuresFromJsonpaths(['$.recursive'])).toEqual([mockRecursiveDisclosure.disclosure]);

        expect(parser.getDisclosuresFromJsonpaths(['$.recursive.stringClaim'])).toEqual(
          expect.arrayContaining([mockRecursiveDisclosure.disclosure, mockStringDisclosure.disclosure]),
        );

        expect(parser.getDisclosuresFromJsonpaths(['$.recursive', '$.recursive.stringClaim'])).toEqual(
          expect.arrayContaining([mockRecursiveDisclosure.disclosure, mockStringDisclosure.disclosure]),
        );
      });

      it('object in array', () => {
        const mockRecursiveDisclosure: Disclosure = {
          disclosure: 'mocked-recursive-disclosure',
          key: null,
          value: {
            _sd: ['sd-hash-2'],
          },
        };

        const sdjwt = {
          claim: [{ '...': 'sd-hash-1' }],
        };

        const digestMap: DigestMap = new Map([
          ['sd-hash-1', mockRecursiveDisclosure],
          ['sd-hash-2', mockStringDisclosure],
        ]);

        const parser = new SDJWTDisclosureStruct({ jwt: sdjwt, digestMap });

        expect(parser.getDisclosuresFromJsonpaths(['$.claim[0]'])).toEqual([mockRecursiveDisclosure.disclosure]);

        expect(parser.getDisclosuresFromJsonpaths(['$.claim[0].stringClaim'])).toEqual(
          expect.arrayContaining([mockRecursiveDisclosure.disclosure, mockStringDisclosure.disclosure]),
        );

        expect(parser.getDisclosuresFromJsonpaths(['$.claim[0]', '$.claim[0].stringClaim'])).toEqual(
          expect.arrayContaining([mockRecursiveDisclosure.disclosure, mockStringDisclosure.disclosure]),
        );
      });

      it('array in object', () => {
        const mockRecursiveDisclosure: Disclosure = {
          disclosure: 'mocked-recursive-disclosure',
          key: 'parent',
          value: [{ '...': 'sd-hash-2' }],
        };

        const sdjwt = {
          _sd: ['sd-hash-1'],
        };

        const digestMap: DigestMap = new Map([
          ['sd-hash-1', mockRecursiveDisclosure],
          ['sd-hash-2', mockArrayItem],
        ]);

        const parser = new SDJWTDisclosureStruct({ jwt: sdjwt, digestMap });

        expect(parser.getDisclosuresFromJsonpaths(['$.parent'])).toEqual([mockRecursiveDisclosure.disclosure]);

        expect(parser.getDisclosuresFromJsonpaths(['$.parent[0]'])).toEqual(
          expect.arrayContaining([mockRecursiveDisclosure.disclosure, mockArrayItem.disclosure]),
        );

        expect(parser.getDisclosuresFromJsonpaths(['$.parent', '$.parent[0]'])).toEqual(
          expect.arrayContaining([mockRecursiveDisclosure.disclosure, mockArrayItem.disclosure]),
        );
      });

      it('array in array', () => {
        const mockRecursiveDisclosure: Disclosure = {
          disclosure: 'mocked-recursive-disclosure',
          key: null,
          value: {
            claim: [{ '...': 'sd-hash-2' }],
          },
        };

        const sdjwt = {
          recursive: [{ '...': 'sd-hash-1' }],
        };

        const digestMap: DigestMap = new Map([
          ['sd-hash-1', mockRecursiveDisclosure],
          ['sd-hash-2', mockArrayItem],
        ]);

        const parser = new SDJWTDisclosureStruct({ jwt: sdjwt, digestMap });

        expect(parser.getDisclosuresFromJsonpaths(['$.recursive[0]'])).toEqual([mockRecursiveDisclosure.disclosure]);

        expect(parser.getDisclosuresFromJsonpaths(['$.recursive[0].claim[0]'])).toEqual(
          expect.arrayContaining([mockRecursiveDisclosure.disclosure, mockArrayItem.disclosure]),
        );

        expect(parser.getDisclosuresFromJsonpaths(['$.recursive[0]', '$.recursive[0].claim[0]'])).toEqual(
          expect.arrayContaining([mockRecursiveDisclosure.disclosure, mockArrayItem.disclosure]),
        );
      });

      it('include recursive parent disclosure', () => {
        const mockRecursiveDisclosure1: Disclosure = {
          disclosure: 'mocked-recursive-disclosure',
          key: 'depth-1',
          value: {
            _sd: ['sd-hash-2'],
          },
        };

        const mockRecursiveDisclosure2: Disclosure = {
          disclosure: 'mocked-recursive-disclosure',
          key: 'depth-2',
          value: {
            _sd: ['sd-hash-3'],
          },
        };

        const mockRecursiveDisclosure3: Disclosure = {
          disclosure: 'mocked-recursive-disclosure',
          key: 'depth-3',
          value: {
            _sd: ['sd-hash-4'],
          },
        };

        const sdjwt = {
          _sd: ['sd-hash-1'],
        };

        const digestMap: DigestMap = new Map([
          ['sd-hash-1', mockRecursiveDisclosure1],
          ['sd-hash-2', mockRecursiveDisclosure2],
          ['sd-hash-3', mockRecursiveDisclosure3],
          ['sd-hash-4', mockStringDisclosure],
        ]);

        const parser = new SDJWTDisclosureStruct({ jwt: sdjwt, digestMap });

        expect(parser.getDisclosuresFromJsonpaths(['$.depth-1'])).toEqual([mockRecursiveDisclosure1.disclosure]);

        expect(parser.getDisclosuresFromJsonpaths(['$.depth-1.depth-2'])).toEqual(
          expect.arrayContaining([mockRecursiveDisclosure1.disclosure, mockRecursiveDisclosure2.disclosure]),
        );

        expect(parser.getDisclosuresFromJsonpaths(['$.depth-1.depth-2.depth-3'])).toEqual(
          expect.arrayContaining([
            mockRecursiveDisclosure1.disclosure,
            mockRecursiveDisclosure2.disclosure,
            mockRecursiveDisclosure3.disclosure,
          ]),
        );

        expect(parser.getDisclosuresFromJsonpaths(['$.depth-1.depth-2.depth-3.stringClaim'])).toEqual(
          expect.arrayContaining([
            mockRecursiveDisclosure1.disclosure,
            mockRecursiveDisclosure2.disclosure,
            mockRecursiveDisclosure3.disclosure,
            mockStringDisclosure.disclosure,
          ]),
        );
      });
    });
  });
});
