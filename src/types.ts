import { JWK, JWTHeaderParameters, JWTPayload } from 'jose';

export interface UnverifiedJWT {
  header: JWTHeaderParameters;
  payload: JWTPayload;
  signature: string;
}

export interface SDJWTPayload extends JWTPayload {
  cnf?: {
    jwk: JWK;
  };
  iss?: string;
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

/**
 * A simple hash function that takes the base64url encoded variant of the disclosure and MUST return a base64url encoded version of the digest
 */
export type Hasher = (data: string) => string;
export type GetHasher = (hashAlg: string) => Promise<Hasher>;

export type Signer = (header: JWTHeaderParameters, payload: JWTPayload) => Promise<string>;
export type Verifier = (data: string) => Promise<boolean>;
export type KeyBindingVerifier = (data: string, key: JWK) => Promise<boolean>;
export type SaltGenerator = (size) => string;

export interface IssueSDJWTOptions {
  signer: Signer;
  hash: {
    alg: string;
    callback: Hasher;
  };
  cnf?: { jwk: JWK };
  generateSalt?: SaltGenerator;
}

export interface VerifySdJwtOptions {
  kb?: {
    verifier?: KeyBindingVerifier;
    skipCheck?: boolean;
  };
}
/**
 * Exported functions
 */

export type DecodeSDJWT = (sdJWT: string) => SDJWT;

/**
 * Unpacks SD-JWT with selective disclosures and returns a JWT with disclosed Claims
 */
export type UnpackSDJWT = (
  sdjwt: SDJWTPayload,
  disclosures: Array<Disclosure>,
  getHasher: GetHasher,
) => Promise<SDJWTPayload>;

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

export type VerifySDJWT = (
  sdjwt: string,
  verifier: Verifier,
  getHasher: GetHasher,
  opts?: VerifySdJwtOptions,
) => Promise<SDJWTPayload>;

export type IssueSDJWT = (
  header: JWTHeaderParameters,
  payload: JWTPayload,
  disclosureFrame: DisclosureFrame,
  opts: IssueSDJWTOptions,
) => Promise<string>;
