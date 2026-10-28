'use strict';

// Local analysis adapter. Uses the existing upstream unpacker unchanged.
// Adds an exact observed version identity in memory; never repacks or flashes.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');

const root = path.resolve(__dirname, '..');
const version = process.argv[2] || '3.2-cn';
const inputs = {
  '3.2-cn': { directory: 'body-3-2-cn', dvr: 'Ver1.42', hash: '92b3f1fda39e37351432d19d0167879f477eb71713a8fbc94b3ba2141ca404e4' },
  '3.1-cn': { directory: 'body-3-1-cn', dvr: 'Ver1.41', hash: '97dfa394efc91f8643c3b1a0673be2dd96590754b29080ce60d3498ebe3d15be' },
};
assert(Object.hasOwn(inputs, version), 'Only the two verified CN inputs are supported');
const input = inputs[version];
const source = path.join(root, 'data/input', input.directory, 'firmware.bin');
const expectedHash = input.hash;
const original = fs.readFileSync(source);
const sha256 = data => crypto.createHash('sha256').update(data).digest('hex');
assert.equal(sha256(original), expectedHash, 'Unexpected input firmware; stop for review');
assert(original.subarray(0, 256).toString('ascii').includes(`C59Y1 VER=M1CN DVR=${input.dvr} `));

const upstream = path.join(root, 'vendor/yi-mirrorless-firmware-tools');
const { versions } = require(path.join(upstream, 'versions.js'));
assert(!versions.some(row => row[0] === 'C59Y1' && row[1] === 'M1CN' && row[2] === input.dvr));
versions.push(['C59Y1', 'M1CN', input.dvr, `${version} (local analysis identity)`]);
const { unpack } = require(path.join(upstream, 'firmware.js'));

const output = path.join(root, 'output', input.directory);
fs.mkdirSync(output, { recursive: true });
const analysisCopy = path.join(output, `m1-${version}.analysis.bin`);
if (fs.existsSync(analysisCopy)) {
  assert.equal(sha256(fs.readFileSync(analysisCopy)), expectedHash, 'Existing analysis copy was modified');
} else {
  fs.writeFileSync(analysisCopy, original, { flag: 'wx' });
}
unpack(analysisCopy, output);

const metadata = JSON.parse(fs.readFileSync(analysisCopy + '.unpack', 'utf8'));
assert.equal(metadata.sections.length, 4, 'Unexpected section count');
assert.deepEqual(metadata.sections.map(s => s.parsedHeader.sectionId || null), [null, 'ND1', 'IPL', 'PTBL']);
assert(metadata.sections[0].subsections.length >= 3, 'Code subsections were not extracted');
assert.equal(sha256(fs.readFileSync(source)), expectedHash, 'Input changed during unpack');

const files = fs.readdirSync(output).sort().map(filename => {
  const data = fs.readFileSync(path.join(output, filename));
  return { filename, bytes: data.length, sha256: sha256(data) };
});
const summary = {
  version,
  inputSha256: expectedHash,
  upstreamCommit: 'b90b96c124a3b076fa0283404e6595a4a40d20d0',
  adapter: 'Runtime version identity only; upstream source and firmware unchanged',
  limitation: 'Upstream decompression is experimental. Checksums do not prove runtime correctness.',
  sections: metadata.sections,
  files,
};
fs.mkdirSync(path.join(root, 'reports'), { recursive: true });
const summaryName = version === '3.2-cn' ? 'unpack-summary.json' : 'unpack-3-1-summary.json';
fs.writeFileSync(path.join(root, 'reports', summaryName), JSON.stringify(summary, null, 2) + '\n');
console.log('Analysis-only unpack complete. Original SHA-256 unchanged. No device access.');
