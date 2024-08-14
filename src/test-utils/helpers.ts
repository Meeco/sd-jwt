import { readdirSync } from 'fs';
import { importJWK } from 'jose';
import { readFile } from 'node:fs/promises';
import { Example, EXAMPLES_DIRECTORY, ISSUER_PUBLIC_KEY, TEST_CASES_DIRECTORY } from './params';

function getDirectory(dirname: string) {
  return readdirSync(dirname, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name);
}

/**
 * './test/example' helpers
 */
export function getExamples() {
  return getDirectory(EXAMPLES_DIRECTORY);
}

/**
 * read example file
 * @param name example name
 * @param file enumerated file type
 */
export async function loadExample(name: string, file: Example) {
  const path = `${EXAMPLES_DIRECTORY}/${name}/${file}`;
  const buffer = await readFile(path);
  return buffer.toString();
}

export async function loadIssuedSDJWT(name) {
  const sdjwt = await loadExample(name, Example.SD_JWT);
  return sdjwt.replace(/\s/g, '');
}

export async function loadSDJWTHeader(name) {
  const sdjwtHeader = await loadExample(name, Example.SD_JWT_HEADER);
  return JSON.parse(sdjwtHeader);
}

export async function loadSDJWTPayload(name) {
  const sdjwtPayload = await loadExample(name, Example.SD_JWT_PAYLOAD);
  return JSON.parse(sdjwtPayload);
}

export async function loadPresentation(name) {
  const sdjwtPresentation = await loadExample(name, Example.SD_JWT_PRESENTATION);
  return sdjwtPresentation.replace(/\s/g, '');
}

export async function loadVerifiedContents(name) {
  const sdjwt = await loadExample(name, Example.VERIFIED_CONTENTS);
  return JSON.parse(sdjwt);
}

export async function loadKeyBindingJWT(name) {
  try {
    const kbjwt = await loadExample(name, Example.KB_JWT_PAYLOAD);
    return JSON.parse(kbjwt);
  } catch (e) {
    return {};
  }
}

export const getIssuerKey = async () => {
  return importJWK(ISSUER_PUBLIC_KEY, 'ES256');
};

/**
 * './test/test-cases' helpers
 */
export function getTestCases() {
  return getDirectory(TEST_CASES_DIRECTORY);
}

export async function loadTestCase(name: string, file: string) {
  const path = `${TEST_CASES_DIRECTORY}/${name}/${file}`;
  const buffer = await readFile(path);
  return buffer.toString();
}

export async function loadClaims(name) {
  const file = await loadTestCase(name, 'claims.json');
  return JSON.parse(file);
}

export async function loadDisclosureFrame(name) {
  const file = await loadTestCase(name, 'disclosureFrame.json');
  return JSON.parse(file);
}
