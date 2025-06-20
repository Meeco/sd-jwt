export const EXAMPLES_DIRECTORY = './test/examples';
export const TEST_CASES_DIRECTORY = './test/test-cases';

export const ISSUER_PUBLIC_KEY = {
  kty: 'EC',
  x: 'b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ',
  y: 'Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8',
  crv: 'P-256',
  d: 'Ur2bNKuBPOrAaxsRnbSH6hIhmNTxSGXshDSUD1a1y7g',
};

/**
 * Files generated by the sd-jwt-generate python script
 */
export enum Example {
  KB_JWT_HEADER = 'kb_jwt_header.json',
  KB_JWT_PAYLOAD = 'kb_jwt_payload.json',
  KB_JWT = 'kb_jwt_serialized.txt',
  SD_JWT = 'sd_jwt_issuance.txt',
  SD_JWT_JWS = 'sd_jwt_jws_part.txt',
  SD_JWT_PAYLOAD = 'sd_jwt_payload.json',
  SD_JWT_HEADER = 'sd_jwt_header.json',
  SD_JWT_PRESENTATION = 'sd_jwt_presentation.txt',
  USER_CLAIMS = 'user_claims.json',
  VERIFIED_CONTENTS = 'verified_contents.json',
}

export const INVALID_JWT = 'INVALID_JWT_EXAMPLE';

export const ISSUER_KEYPAIR = {
  PUBLIC_KEY_JWK: {
    kty: 'EC',
    x: 'QxM0mbg6Ow3zTZZjKMuBv-Be_QsGDfRpPe3m1OP90zk',
    y: 'aR-Qm7Ckg9TmtcK9-miSaMV2_jd4rYq6ZsFRNb8dZ2o',
    crv: 'P-256',
  },
  PRIVATE_KEY_JWK: {
    kty: 'EC',
    x: 'QxM0mbg6Ow3zTZZjKMuBv-Be_QsGDfRpPe3m1OP90zk',
    y: 'aR-Qm7Ckg9TmtcK9-miSaMV2_jd4rYq6ZsFRNb8dZ2o',
    crv: 'P-256',
    d: 'fWfGrvu1tUqnyYHrdlpZiBsxkMoeim3EleoPEafV_yM',
  },
};

export const COMPLEX_SD_JWT =
  'eyJhbGciOiAiRVMyNTYifQ.eyJfc2QiOiBbIi0yeU9mV01lWkZRYXFmWkJoakdmLVRYLXFCTnZrS3hjaUZvaWVkc0k1XzgiLCAiOGdKWjFDdHFwb0lvbjB2OVpJN0JNR3QxcGJHbUFzTkk4YzA3X3cxT2NTWSIsICJRRGgtSVdORmZHLU5nbEU1WnNCd2lkNFpTQmpKQlVSWmV5TkprZnRaZ0tnIl0sICJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXIiLCAiaWF0IjogMTY4MzAwMDAwMCwgImV4cCI6IDE4ODMwMDAwMDAsICJ2ZXJpZmllZF9jbGFpbXMiOiB7InZlcmlmaWNhdGlvbiI6IHsiX3NkIjogWyI3aDRVRTlxU2N2REtvZFhWQ3VvS2ZLQkpwVkJmWE1GX1RtQUdWYVplM1NjIiwgInZUd2UzcmFISUZZZ0ZBM3hhVUQyYU14Rno1b0RvOGlCdTA1cUtsT2c5THciXSwgInRydXN0X2ZyYW1ld29yayI6ICJkZV9hbWwiLCAiZXZpZGVuY2UiOiBbeyJfc2QiOiBbIjl3cGpWUFd1RDdQSzBuc1FETDhCMDZsbWRnVjNMVnliaEh5ZFFwVE55TEkiLCAiRzVFbmhPQU9vVTlYXzZRTU52ekZYanBFQV9SYy1BRXRtMWJHX3djYUtJayIsICJJaHdGcldVQjYzUmNacTl5dmdaMFhQYzdHb3doM08ya3FYZUJJc3dnMUI0IiwgIldweFE0SFNvRXRjVG1DQ0tPZURzbEJfZW11Y1lMejJvTzhvSE5yMWJFVlEiXX1dfSwgImNsYWltcyI6IHsiX3NkIjogWyJCbGY3REJtZEhFelpNUUh3OHkxMXpDTEFfNzZIZXNaNjBjeGZoQ0ExaE5VIiwgIkZuTTFZLWVWcVdpLWg2UDl6ekFyYjM1bGZDNDNTalYtWnE5TkpNQXhTSGMiLCAiYzQ2bjBUejRLWTBjNndOZjVkUTFvVWo0N3MxNmhiOE51Rk1xZW85OF9IMCIsICJoT0l5M1NNaV93TS1TSk93bXYwX3NreWZwaWhkM244anlHWnc1NnppY3lNIiwgIm0xa3FhQ3dnS3pLbWI5dTQwYm1SMEptM0h2VXVpakUtT0NBdC1nb1FUWDgiLCAieTUwY3pjMElTQ2h5X2JzYmExZE1vVXVBT1E1QU1tT1NmR29FZTgxdjFGVSJdfX0sICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fX0.mF1_pvV2a222ALY09Ub1VWAEykb-7FGlonxMka6hQ-YN4dq3r93xYHK0_ut4VdS8n8SUrvOu2GOfQtqaWL71lA~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInRpbWUiLCAiMjAxMi0wNC0yM1QxODoyNVoiXQ~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgInZlcmlmaWNhdGlvbl9wcm9jZXNzIiwgImYyNGM2Zi02ZDNmLTRlYzUtOTczZS1iMGQ4NTA2ZjNiYzciXQ~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgInR5cGUiLCAiZG9jdW1lbnQiXQ~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgIm1ldGhvZCIsICJwaXBwIl0~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInRpbWUiLCAiMjAxMi0wNC0yMlQxMTozMFoiXQ~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImRvY3VtZW50IiwgeyJ0eXBlIjogImlkY2FyZCIsICJpc3N1ZXIiOiB7Im5hbWUiOiAiU3RhZHQgQXVnc2J1cmciLCAiY291bnRyeSI6ICJERSJ9LCAibnVtYmVyIjogIjUzNTU0NTU0IiwgImRhdGVfb2ZfaXNzdWFuY2UiOiAiMjAxMC0wMy0yMyIsICJkYXRlX29mX2V4cGlyeSI6ICIyMDIwLTAzLTIyIn1d~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImdpdmVuX25hbWUiLCAiTWF4Il0~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgImZhbWlseV9uYW1lIiwgIk1cdTAwZmNsbGVyIl0~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIm5hdGlvbmFsaXRpZXMiLCBbIkRFIl1d~WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgImJpcnRoZGF0ZSIsICIxOTU2LTAxLTI4Il0~WyI1YlBzMUlxdVpOYTBoa2FGenp6Wk53IiwgInBsYWNlX29mX2JpcnRoIiwgeyJjb3VudHJ5IjogIklTIiwgImxvY2FsaXR5IjogIlx1MDBkZXlra3ZhYlx1MDBlNmphcmtsYXVzdHVyIn1d~WyI1YTJXMF9OcmxFWnpmcW1rXzdQcS13IiwgImFkZHJlc3MiLCB7ImxvY2FsaXR5IjogIk1heHN0YWR0IiwgInBvc3RhbF9jb2RlIjogIjEyMzQ0IiwgImNvdW50cnkiOiAiREUiLCAic3RyZWV0X2FkZHJlc3MiOiAiV2VpZGVuc3RyYVx1MDBkZmUgMjIifV0~WyJ5MXNWVTV3ZGZKYWhWZGd3UGdTN1JRIiwgImJpcnRoX21pZGRsZV9uYW1lIiwgIlRpbW90aGV1cyJd~WyJIYlE0WDhzclZXM1FEeG5JSmRxeU9BIiwgInNhbHV0YXRpb24iLCAiRHIuIl0~WyJDOUdTb3VqdmlKcXVFZ1lmb2pDYjFBIiwgIm1zaXNkbiIsICI0OTEyMzQ1Njc4OSJd~';

export const COMPLEX_SD_JWT_DISCLOSURE_JSONPATHS = {
  '$.birth_middle_name': 'Timotheus',
  '$.msisdn': '49123456789',
  '$.salutation': 'Dr.',
  '$.verified_claims.claims.address': {
    country: 'DE',
    locality: 'Maxstadt',
    postal_code: '12344',
    street_address: 'Weidenstraße 22',
  },
  '$.verified_claims.claims.birthdate': '1956-01-28',
  '$.verified_claims.claims.family_name': 'Müller',
  '$.verified_claims.claims.given_name': 'Max',
  '$.verified_claims.claims.nationalities': ['DE'],
  '$.verified_claims.claims.place_of_birth': { country: 'IS', locality: 'Þykkvabæjarklaustur' },
  '$.verified_claims.verification.evidence[0].document': {
    date_of_expiry: '2020-03-22',
    date_of_issuance: '2010-03-23',
    issuer: { country: 'DE', name: 'Stadt Augsburg' },
    number: '53554554',
    type: 'idcard',
  },
  '$.verified_claims.verification.evidence[0].method': 'pipp',
  '$.verified_claims.verification.evidence[0].time': '2012-04-22T11:30Z',
  '$.verified_claims.verification.evidence[0].type': 'document',
  '$.verified_claims.verification.time': '2012-04-23T18:25Z',
  '$.verified_claims.verification.verification_process': 'f24c6f-6d3f-4ec5-973e-b0d8506f3bc7',
};

export const ARRAY_SD_JWT =
  'eyJhbGciOiAiRVMyNTYifQ.eyJfc2QiOiBbInNHbVYydFNMSG1KU2NFVGV2WGdUUS1iTTdPNVpuUXV1LXlwcUkydkItSlUiXSwgImlzcyI6ICJodHRwczovL2V4YW1wbGUuY29tL2lzc3VlciIsICJpYXQiOiAxNjgzMDAwMDAwLCAiZXhwIjogMTg4MzAwMDAwMCwgInN1YiI6ICJqb2huX2RvZV80MiIsICJuYXRpb25hbGl0aWVzIjogW3siLi4uIjogImk3ZUtkSGNfWk1PbmhpeXUzVEpqNUdWRFE3WndKT01YRkQzWGdVYm84R1EifSwgeyIuLi4iOiAidXNXWEZQS2FxS01yZVRyajcyUUQyNHdCOHhjN2xRNHpDbnJubjhaUlZlbyJ9LCAiREUiXSwgImlzX292ZXIiOiB7Il9zZCI6IFsiMm92TUpSX1pOTUI2bmdGSzNTVVFuUklneU01NDhEelI3dEpGVE8tWnpCTSIsICJDZVZxeFZVVkhwdmE1WHAwWC1OZVV2aGl4akRZcDdQVFo0QmFGV0dYVWVrIiwgImRnMXBCSlYtZEFCaWxxRDJSWWlHOHo0Z1J0dURGZFJCZGx3SGdkTEZFeDgiXX0sICJhZGRyZXNzZXMiOiBbeyJzdHJlZXQiOiAiMTIzIE1haW4gU3QiLCAiY2l0eSI6ICJBbnl0b3duIiwgInN0YXRlIjogIk5ZIiwgInppcCI6ICIxMjM0NSIsICJ0eXBlIjogIm1haW5fYWRkcmVzcyJ9LCB7Ii4uLiI6ICJSTldjeFBEOEExWmhBbTZfd0FpSlNvU3pJUmJfdzFRVWFLR3ZTMjQwSy1ZIn1dLCAibnVsbF92YWx1ZXMiOiBbbnVsbCwgeyIuLi4iOiAiaGhCNXB6aVM0czBkU3gwa3FsMzF2RHR1bzNKVkRmQjRWWi1ZSGNqMkE5TSJ9LCB7Ii4uLiI6ICJvX1ZGUmx1QTE5MHdySDVFMXlyMnIzOVV5VG54My1tM3FQUkVpa1NyNlFvIn0sIG51bGxdLCAiZGF0YV90eXBlcyI6IFt7Ii4uLiI6ICJuWTcyUDZWNXVIUWUtQllrd1lqLXBhRzJ5M2ZtajYxNEZLUVFoaGs2VDFFIn0sIHsiLi4uIjogInp0N2tXUHRaVHBNWUtQb2FRZC1MNzFMLWFLWU1ZWU5MT0ZPZi15SDN1TFkifSwgeyIuLi4iOiAiSzF5eEhKNHoxMEpLZDJqUm1RdXppQ3ltM0Qxb1hCME5hRlZMSEVPdjhYTSJ9LCB7Ii4uLiI6ICJ5ci0xTkRoQWFGWVB2THJBenZkRmZCd1JKU193bjE5OUpYMGFkRFlhNkFrIn0sIHsiLi4uIjogIk5vVE9UaldxMV9jWXUza2ZRS2gzaldyeDlPTFNJSWRoWVgwXzkyLVJELVkifSwgeyIuLi4iOiAiYmlCTENQNDI0Q29EWVRwQm1kZW4tekdtWU9kRTBHU0hsZXJTYW9ZZVFaMCJ9LCB7Ii4uLiI6ICJfei1XZV9nYnZLbzg0anB1aEJRUzl2OXlWaERvMi0tRkNETldNSE1lelVRIn1dLCAibmVzdGVkX2FycmF5IjogW1t7Ii4uLiI6ICJGYkpfV19NLUdsOXJNVVI4ZmNzTUZkaUhWLXFFYWJpVC11OWVIdk5LU0FBIn0sIHsiLi4uIjogInpvNm11ekZRSjlVQ2VGdXkzRHFfWUluUXpMR2ltSlZJenRIR250V1Z4dzAifV0sIFt7Ii4uLiI6ICJuLVRPUUR1cjlFQTJrOUdfVlZxbHZrT1lDeklGYjI4TEtBOTlJYVFmRnQ4In0sIHsiLi4uIjogInh2SjdOd2hSWTkzVXFoY3FWS0YtQXA3SHdacEtlMXJhRVdaZ19Xb3pCQnMifV1dLCAiYXJyYXlfd2l0aF9yZWN1cnNpdmVfc2QiOiBbImJvcmluZyIsIHsiLi4uIjogIktJSzlGT1EzQy1qTHhHVzlvUllUTC1BRVRGM2VHb2xQOGx5VlJWRk9xWDgifSwgW3siLi4uIjogInVOOERZdFQ2OERvM01BTzlkZVRhZ1daeC1ha2dkNkRtekk0eDl4Rk43YnMifSwgeyIuLi4iOiAiRjVTVFg2NDUyQXc5VlF5Rmg1dmNsWC1TbFVBdXVfcl9heC1vdzM1ZTRKdyJ9XV0sICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fX0.AoX_2VJi8MmwPvPNqRIXmMI_HBuuyTa2MbB3tfD2G1FR5kmBnUJI1Itm_ECD8TwA8v2XjDOUc-L4aywrac7O7Q~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgIlVTIl0~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgIkNBIl0~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgIjEzIiwgdHJ1ZV0~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgIjE4IiwgZmFsc2Vd~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgIjIxIiwgZmFsc2Vd~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgeyJzdHJlZXQiOiAiNDU2IE1haW4gU3QiLCAiY2l0eSI6ICJBbnl0b3duIiwgInN0YXRlIjogIk5ZIiwgInppcCI6ICIxMjM0NSIsICJ0eXBlIjogInNlY29uZGFyeV9hZGRyZXNzIn1d~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgbnVsbF0~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgbnVsbF0~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgbnVsbF0~WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgNDJd~WyI1YlBzMUlxdVpOYTBoa2FGenp6Wk53IiwgMy4xNF0~WyI1YTJXMF9OcmxFWnpmcW1rXzdQcS13IiwgImZvbyJd~WyJ5MXNWVTV3ZGZKYWhWZGd3UGdTN1JRIiwgdHJ1ZV0~WyJIYlE0WDhzclZXM1FEeG5JSmRxeU9BIiwgWyJUZXN0Il1d~WyJDOUdTb3VqdmlKcXVFZ1lmb2pDYjFBIiwgeyJmb28iOiAiYmFyIn1d~WyJreDVrRjE3Vi14MEptd1V4OXZndnR3IiwgImZvbyJd~WyJIM28xdXN3UDc2MEZpMnllR2RWQ0VRIiwgImJhciJd~WyJPQktsVFZsdkxnLUFkd3FZR2JQOFpBIiwgImJheiJd~WyJNMEpiNTd0NDF1YnJrU3V5ckRUM3hBIiwgInF1eCJd~WyJEc210S05ncFY0ZEFIcGpyY2Fvc0F3IiwgImJheiIsIHsicXV4IjogInF1dXgifV0~WyJlSzVvNXBIZmd1cFBwbHRqMXFoQUp3IiwgeyJfc2QiOiBbIjZaU1pWRFg0VGVMNXlwbGthN1JJdDF3X1ZfQkEyZWJJMDQxQUVvZC1JQUkiXSwgImZvbyI6ICJiYXIifV0~WyJqN0FEZGIwVVZiMExpMGNpUGNQMGV3IiwgImZvbyJd~WyJXcHhKckZ1WDh1U2kycDRodDA5anZ3IiwgImJhciJd~WyJhdFNtRkFDWU1iSlZLRDA1bzNKZ3RRIiwgInNkX2FycmF5IiwgWzMyLCAyM11d~';

export const INVALID_DISCLOSURE_ARRAY_SD_JWT_EXAMPLES = [
  {
    disclosureArray: ['salt', 'some-value'],
  },
  {
    disclosureArray: ['salt', null, 'some-value'],
  },
  {
    disclosureArray: ['salt', 123, 'some-value'],
  },
  {
    disclosureArray: ['salt', '', 'some-value'],
  },
];
