/**
 * Re-signs the Key Binding JWT of every test/examples presentation that carries one.
 *
 * The fixtures were generated against a draft that predates RFC 9901: their KB-JWTs
 * have no sd_hash claim and no kb+jwt typ header, so verifySDJWT now rejects them.
 * This script keeps the Issuer-signed JWT and the Disclosures byte for byte, and
 * replaces only the KB-JWT, adding the sd_hash over the presented SD-JWT.
 *
 * The holder key is the one from the SD-JWT specification examples, which is what
 * the fixtures carry in cnf.jwk.
 *
 * Usage: node tools/regenerate-kb-jwt.mjs
 */
import { createHash } from 'crypto';
import { readdirSync, readFileSync, writeFileSync } from 'fs';
import { importJWK, SignJWT } from 'jose';

const EXAMPLES_DIRECTORY = './test/examples';
const PRESENTATION_FILE = 'sd_jwt_presentation.txt';
const SEPARATOR = '~';

const HOLDER_PRIVATE_KEY_JWK = {
  kty: 'EC',
  crv: 'P-256',
  x: 'TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc',
  y: 'ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ',
  d: '5K5SCos8zf9zRemGGUl6yfok-_NiiryNZsvANWMhF-I',
};

const base64urlDecode = (input) => Buffer.from(input, 'base64url').toString('utf8');
const sha256 = (data) => createHash('sha256').update(data).digest().toString('base64url');

/** The fixtures are stored wrapped; keep the width they already use. */
const wrap = (text, width) => text.replace(new RegExp(`(.{1,${width}})`, 'g'), '$1\n');

const holderKey = await importJWK(HOLDER_PRIVATE_KEY_JWK, 'ES256');

for (const example of readdirSync(EXAMPLES_DIRECTORY, { withFileTypes: true }).filter((e) => e.isDirectory())) {
  const path = `${EXAMPLES_DIRECTORY}/${example.name}/${PRESENTATION_FILE}`;
  const stored = readFileSync(path, 'utf8');
  const presentation = stored.replace(/\s/g, '');

  const keyBindingJWT = presentation.slice(presentation.lastIndexOf(SEPARATOR) + 1);

  if (!keyBindingJWT) {
    console.log(`${example.name}: no KB-JWT, left untouched`);
    continue;
  }

  const presentationWithoutKBJWT = presentation.slice(0, presentation.lastIndexOf(SEPARATOR) + 1);
  const { sd_hash: _dropped, ...claims } = JSON.parse(base64urlDecode(keyBindingJWT.split('.')[1]));

  const newKeyBindingJWT = await new SignJWT({ ...claims, sd_hash: sha256(presentationWithoutKBJWT) })
    .setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' })
    .sign(holderKey);

  const width = stored.split('\n')[0].length;
  writeFileSync(path, wrap(`${presentationWithoutKBJWT}${newKeyBindingJWT}`, width));

  console.log(`${example.name}: KB-JWT re-signed with sd_hash`);
}
