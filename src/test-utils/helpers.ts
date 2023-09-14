import { readFile } from 'node:fs/promises';
import { readdirSync } from 'fs';
import { Example, EXAMPLES_DIRECTORY, ISSUER_PUBLIC_KEY } from './params';
import { importJWK } from 'jose';

// helper
function getFilePath(name: string, file: Example) {
  return `${EXAMPLES_DIRECTORY}/${name}/${file}`;
}

/**
 * List directories under EXAMPLES_DIRECTORY
 */
export function getExamples() {
  return readdirSync(EXAMPLES_DIRECTORY, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name);
}

/**
 * read example file
 * @param name example name
 * @param file enumerated file type
 */
export async function loadExample(name: string, file: Example) {
  const path = getFilePath(name, file);
  const buffer = await readFile(path);
  return buffer.toString();
}

export async function loadIssuedSDJWT(name) {
  const sdjwt = await loadExample(name, Example.SD_JWT);
  return sdjwt.replace(/\s/g, '');
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

export const getIssuerKey = async () => {
  return importJWK(ISSUER_PUBLIC_KEY, 'ES256');
};
