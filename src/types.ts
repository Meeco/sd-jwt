import { JWK, JWTPayload, KeyLike } from 'jose';

export interface SDJWTPayload extends JWTPayload {
  cnf?: {
    jwk: JWK;
  };
}

export interface Disclosure {
  disclosure: string;
  key: string;
  value: any;
}

export interface SDJWT {
  unverifiedInputSdJwt: SDJWTPayload;
  disclosures: Disclosure[];
  keyBindingJWT?: string;
}

export interface SdDigestHashmap {
  [sd_digest: string]: Disclosure;
}

/**
 * Exported functions
 */
export type DecodeSDJWT = (sdJWT: string) => SDJWT;

export type UnpackSDJWT = (sdJWT: SDJWTPayload, disclosures: Array<Disclosure>) => SDJWTPayload;

type GetIssuerKeyCallback = (issuer: string) => Promise<KeyLike | Uint8Array>;

interface VerifySdJwtOptions {
  getIssuerKey: GetIssuerKeyCallback;
  expected_aud?: string;
  expected_nonce?: string;
}
export type VerifySDJWT = (
  sdJWT: string,
  { getIssuerKey, expected_aud, expected_nonce }: VerifySdJwtOptions,
) => Promise<SDJWTPayload>;
