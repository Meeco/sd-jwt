export interface JWK {
  /** JWK "alg" (Algorithm) Parameter. */
  alg?: string;
  crv?: string;
  d?: string;
  dp?: string;
  dq?: string;
  e?: string;
  /** JWK "ext" (Extractable) Parameter. */
  ext?: boolean;
  k?: string;
  /** JWK "key_ops" (Key Operations) Parameter. */
  key_ops?: string[];
  /** JWK "kid" (Key ID) Parameter. */
  kid?: string;
  /** JWK "kty" (Key Type) Parameter. */
  kty?: string;
  n?: string;
  oth?: Array<{
    d?: string;
    r?: string;
    t?: string;
  }>;
  p?: string;
  q?: string;
  qi?: string;
  /** JWK "use" (Public Key Use) Parameter. */
  use?: string;
  x?: string;
  y?: string;
  /** JWK "x5c" (X.509 Certificate Chain) Parameter. */
  x5c?: string[];
  /** JWK "x5t" (X.509 Certificate SHA-1 Thumbprint) Parameter. */
  x5t?: string;
  /** "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Parameter. */
  'x5t#S256'?: string;
  /** JWK "x5u" (X.509 URL) Parameter. */
  x5u?: string;
  [propName: string]: unknown;
}

export interface JWTHeaderParameters {
  /** "kid" (Key ID) Header Parameter. */
  kid?: string;
  /** "x5t" (X.509 Certificate SHA-1 Thumbprint) Header Parameter. */
  x5t?: string;
  /** "x5c" (X.509 Certificate Chain) Header Parameter. */
  x5c?: string[];
  /** "x5u" (X.509 URL) Header Parameter. */
  x5u?: string;
  /** "jku" (JWK Set URL) Header Parameter. */
  jku?: string;
  /** "jwk" (JSON Web Key) Header Parameter. */
  jwk?: Pick<JWK, 'kty' | 'crv' | 'x' | 'y' | 'e' | 'n'>;
  /** "typ" (Type) Header Parameter. */
  typ?: string;
  /** "cty" (Content Type) Header Parameter. */
  cty?: string;
  /** JWS "crit" (Critical) Header Parameter. */
  crit?: string[];
  /** Any other JWS Header member. */
  [propName: string]: unknown;
  /** JWS "alg" (Algorithm) Header Parameter. */
  alg: string;
  /**
   * This JWS Extension Header Parameter modifies the JWS Payload representation and the JWS Signing
   * Input computation as per {@link https://www.rfc-editor.org/rfc/rfc7797 RFC7797}.
   */
  b64?: true;
}

export interface JWTPayload {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  jti?: string;
  nbf?: number;
  exp?: number;
  iat?: number;
  [propName: string]: unknown;
}

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
  unverifiedInputSDJWT: SDJWTPayload;
  disclosures: Disclosure[];
  keyBindingJWT?: string;
}

export type CompactSDJWT = string;

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
  _decoyCount?: number;
};

export type PackedClaims = {
  _sd?: Array<string>;
  [key: string]: any | unknown;
};

export type SelectiveDiscloseableArrayItem = {
  // disclosure.string
  _sd: string;
  // disclosure.value
  '...': SelectiveDisclosableClaims | any;
};

export type SelectiveDisclosableClaims = {
  // disclosure.string
  _sd?: string;
  [key: string]: SelectiveDisclosableClaims | Array<SelectiveDiscloseableArrayItem | any> | unknown;
};

export type DisclosureMap = {
  [sdDigest: string]: {
    disclosure: string;
    parentDisclosures: string[];
    value: any;
  };
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

export interface VerifySDJWTOptions {
  kb?: {
    verifier?: KeyBindingVerifier;
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
  options?: {
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
  opts?: VerifySDJWTOptions,
) => Promise<SDJWTPayload>;

export type IssueSDJWT = (
  header: JWTHeaderParameters,
  payload: JWTPayload,
  disclosureFrame: DisclosureFrame,
  opts: IssueSDJWTOptions,
) => Promise<string>;

export type CreateSDMap = (
  sdjwt: string,
  hasher: Hasher,
) => {
  sdMap: SelectiveDisclosableClaims;
  disclosureMap: DisclosureMap;
};
