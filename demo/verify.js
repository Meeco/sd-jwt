const crypto = require('crypto');
const { verifySDJWT } = require('../dist/node/cjs');
const { loadFile, writeFile, hasher } = require('./helper');

const verify = async () => {
  const presentation = await loadFile('output/presentation.jwt');
  const verifier = () => true;
  const getHasher = () => hasher;

  const result = await verifySDJWT(presentation, verifier, getHasher);

  writeFile('output/disclosed.json', JSON.stringify(result));
}

verify();