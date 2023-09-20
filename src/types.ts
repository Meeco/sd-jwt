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

export interface DisclosureClaim {
  key?: string;
  value: any;
}

type ArrayIndex = number;
export type DisclosureFrame = {
  [key: string | ArrayIndex]: DisclosureFrame | unknown;
  _sd?: Array<string | ArrayIndex>;
};

export type PackedClaims = {
  _sd?: Array<string>;
  [key: string]: any | unknown;
};

export type Hasher = (data: string) => Promise<string>;
export type SaltGenerator = (size) => string;
/**
 * Exported functions
 */
export type DecodeSDJWT = (sdJWT: string) => SDJWT;

export type UnpackSDJWT = (sdJWT: SDJWTPayload, disclosures: Array<Disclosure>) => SDJWTPayload;

export type PackSDJWT = (
  claims: object | Array<any>,
  disclosureFrame: DisclosureFrame,
  hasher: Hasher,
  options: {
    generateSalt?: SaltGenerator;
  },
) => Promise<{
  claims: PackedClaims;
  disclosures: Array<string>;
}>;

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
