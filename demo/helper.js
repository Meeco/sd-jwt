const crypto = require('crypto');
const fs = require('fs');
const { readFile } = require('node:fs/promises');

async function loadFile(filepath) {
  const buffer = await readFile(filepath);
  return buffer.toString();
}

async function loadJSON(filepath) {
  const content = await loadFile(filepath);
  return JSON.parse(content);
}

function writeFile(filename, content) {
  return fs.writeFileSync(filename, content);
}

function base64encode(input) {
  return Buffer.from(input).toString('base64url');
}

function base64decode(input) {
  return Buffer.from(input, 'base64url').toString();
}

const hasher = (data) => {
  const digest = crypto.createHash('sha256').update(data).digest();
  return base64encode(digest);
};

module.exports = {
  loadFile,
  loadJSON,
  writeFile,
  base64encode,
  base64decode,
  hasher
}