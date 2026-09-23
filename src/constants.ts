export const SD_DIGEST = '_sd';
export const SD_HASH_ALG = '_sd_alg';
/**
 * @deprecated use SD_DECOY instead.
 */
export const SD_DECOY_COUNT = '_decoyCount';
export const SD_DECOY = '_sd_decoy';
export const DEFAULT_SD_HASH_ALG = 'sha-256';
// IANA Named Information Hash Algorithm registry.
export const SUPPORTED_SD_HASH_ALGS = ['sha-256', 'sha-384', 'sha-512', 'sha3-256', 'sha3-384', 'sha3-512'];
export const FORMAT_SEPARATOR = '~';
export const KB_JWT_TYPE_HEADER = 'kb+jwt';
export const SD_LIST_PREFIX = '...';
export const SD_JWT_TYPE = 'sd+jwt';
export const FORBIDDEN_KEYS_IN_DISCLOSURE = [SD_DIGEST, SD_LIST_PREFIX];
