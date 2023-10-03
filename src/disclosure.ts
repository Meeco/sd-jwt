import { decodeSDJWT } from './common';
import { createDisclosureMap, createHashMapping, unpackClaims } from './helpers';
import { CreateSDMap } from './types';

export const createSDMap: CreateSDMap = (sdjwt, hasher) => {
  const { unverifiedInputSdJwt: payload, disclosures } = decodeSDJWT(sdjwt);
  const disclosureMap = createDisclosureMap(disclosures, hasher);
  const map = createHashMapping(disclosures, hasher);
  const sdMap = unpackClaims(payload, map);

  return {
    sdMap,
    disclosureMap,
  };
};
