import { splitSDJWT } from './common.js';
import { SD_DIGEST, SD_LIST_PREFIX } from './constants.js';
import { combineSDJWT, decodeDisclosure, decodeJWT, isObject } from './helpers.js';
import { Disclosure, GetHasher, Hasher } from './types.js';

export type DigestMap = Map<string, Disclosure>;

type getDisclosuresOptions = {
  ignoreInvalidJsonpath?: boolean;
};

/**
 * List and Retrieve Disclosures using
 * Explicit dot-notation JSONpath expression
 */
export class SDJWTDisclosureStruct {
  readonly jwt: object;
  readonly digestMap: DigestMap;

  // Map<jsonpath, digest>
  private jsonpathMap: Map<string, string> = new Map();

  // Map<childDigest, parentDigest>
  private parentMap: Map<string, string> = new Map();

  constructor({ jwt, digestMap }: { jwt: object; digestMap: DigestMap }) {
    this.jwt = jwt;
    this.digestMap = digestMap;

    this.parse();
  }

  public listDisclosureJsonPaths() {
    const list = {};

    this.jsonpathMap.forEach((value, key) => {
      const disclosure = this.digestMap.get(value);
      list[key] = disclosure.value;
    });

    return list;
  }

  public getDisclosuresFromJsonpaths(disclosuresJsonpath: string[], opts?: getDisclosuresOptions) {
    const digests = disclosuresJsonpath.map((jsonpath) => {
      const digest = this.jsonpathMap.get(jsonpath.startsWith('$.') ? jsonpath : '$.' + jsonpath);

      if (!opts?.ignoreInvalidJsonpath && !digest) {
        throw new Error(`Cannot find disclosure for provided jsonpath ${jsonpath}`);
      }

      return digest;
    });

    const selectedDigests = new Set();

    digests.forEach((digest) => {
      selectedDigests.add(digest);
      const parentDigests = this.getParentDigests(digest);
      parentDigests.forEach((digest: string) => selectedDigests.add(digest));
    });

    const disclosures = [...selectedDigests].map((digest: string) => this.digestMap.get(digest)?.disclosure);

    return disclosures;
  }

  private parse() {
    this.objectTraverse(this.jwt);
  }

  private parseSdDigest(digest: string, parent = null, pathname = '$') {
    const disclosure = this.digestMap.get(digest);
    if (disclosure) {
      if (parent) {
        this.parentMap.set(digest, parent);
      }

      // if key is missing; disclosure is an array item;
      const jsonpath = disclosure.key ? `${pathname}.${disclosure.key}` : pathname;
      this.jsonpathMap.set(jsonpath, digest);

      this.objectTraverse(disclosure.value, digest, jsonpath);
    }
  }

  private objectTraverse(obj, parent = null, pathname = '$') {
    if (obj instanceof Array) {
      return this.arrayTraverse(obj, parent, pathname);
    }

    if (!isObject(obj)) {
      return;
    }

    for (const key in obj) {
      if (key !== SD_DIGEST && key !== SD_LIST_PREFIX && obj[key] instanceof Object) {
        this.objectTraverse(obj[key], parent, `${pathname}.${key}`);
      }
    }

    if (obj[SD_DIGEST]) {
      obj[SD_DIGEST].forEach((digest) => {
        this.parseSdDigest(digest, parent, pathname);
      });
    }
  }

  private arrayTraverse(arr, parent = null, pathname = '$') {
    arr.forEach((item, index) => {
      const jsonpath = `${pathname}[${index}]`;

      if (item instanceof Array) {
        return this.arrayTraverse(item, parent, jsonpath);
      }

      if (isObject(item) && !item[SD_LIST_PREFIX]) {
        return this.objectTraverse(item, parent, jsonpath);
      }

      return this.parseSdDigest(item[SD_LIST_PREFIX], parent, jsonpath);
    });
  }

  private getParentDigests(digest: string, collection: string[] = []) {
    if (!digest) {
      return collection;
    }

    const parent = this.parentMap.get(digest);

    if (parent) {
      collection.push(parent);
    }

    return this.getParentDigests(parent, collection);
  }
}

export class SDJsonpath {
  private static getParser({ jwt, digestMap }) {
    return new SDJWTDisclosureStruct({ jwt, digestMap });
  }

  static fromJWT(jwt: object, disclosures: string[], hasher: Hasher) {
    const digestMap = createDigestMap(disclosures, hasher);
    return this.getParser({ jwt, digestMap }).listDisclosureJsonPaths();
  }

  static async fromCompactJWT(sdjwt: string, getHasher: GetHasher) {
    const { jwt, disclosures, keyBindingJWT: _kbjwt } = splitSDJWT(sdjwt);

    const { payload } = decodeJWT(jwt);
    const hasher = await getHasher(payload._sd_alg as string);

    return this.fromJWT(payload, disclosures, hasher);
  }

  static async getJWT(sdjwt: string, jsonpaths: string[], getHasher: GetHasher, parserOptions?: getDisclosuresOptions) {
    const { jwt, disclosures, keyBindingJWT: _kbjwt } = splitSDJWT(sdjwt);

    const { payload } = decodeJWT(jwt);
    const hasher = await getHasher(payload._sd_alg as string);
    const digestMap = createDigestMap(disclosures, hasher);

    const selectedDisclosures = this.getParser({ jwt: payload, digestMap }).getDisclosuresFromJsonpaths(
      jsonpaths,
      parserOptions,
    );

    return combineSDJWT(jwt, selectedDisclosures);
  }
}

export const createDigestMap = (disclosures: string[], hasher: Hasher): DigestMap => {
  const map: DigestMap = new Map();

  disclosures.forEach((d) => {
    const digest = hasher(d);
    map.set(digest, decodeDisclosure(d));
  });

  return map;
};
