const fs = require('fs');
const { loadJSON, base64decode, writeFile, hasher } = require('./helper');
const { issueSDJWT } = require('../dist/node/cjs');

const generateDisclosureMD = (disclosures, filename) => {
  const file = fs.createWriteStream(filename);

  disclosures.forEach((d) => {
    const disclosure = base64decode(d);
    const arr = JSON.parse(disclosure);

    if (arr.length == 2) {
      file.write('__Array Entry__:  \n\n');
    } else {
      file.write('__Claim `'+arr[1]+'`__:help  \n\n');
    }

    const hash = hasher(d);
    file.write(' * SHA-256 Hash: `'+hash+'`  \n');
    file.write(' * Disclosure:  \n');
    file.write(' `'+d+'`  \n');
    file.write(' * Contents:');
    file.write(' `'+disclosure+'`  \n');
    file.write('\n\n');
  });

  file.end();
}

const issue = async () => {
  const claims = await loadJSON('example/claims.json');
  const disclosureFrame = await loadJSON('example/claims.sd.json');

  const signer = () => 'DEMO_SIGNATURE';

  const result = await issueSDJWT({ alg: 'ES256' }, claims, disclosureFrame, { signer, hash: {
    alg: 'sha-256',
    callback: hasher
  }});

  writeFile('output/issued.jwt', result);
  writeFile('output/presentation.jwt', result);

  [header, payload, signature] = result.split('.');

  writeFile('output/issued.json', base64decode(payload));

  const disclosures = signature.split('~');
  disclosures.shift();
  disclosures.pop();

  generateDisclosureMD(disclosures, 'output/disclosures.md');
}

issue();