'use strict';
// 只读比较两个官方版本；自写常见 CRC 参数扫描，不假定末尾字是校验值。
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const root = path.resolve(__dirname, '..');
process.env.TMP = process.env.TEMP = path.join(root, 'temp/codex-tmp');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const must = (c, msg) => { if (!c) throw Error(msg); };
const specs = [
  ['IEEE', 0x04c11db7, 0xedb88320], ['Castagnoli', 0x1edc6f41, 0x82f63b78],
  ['Koopman', 0x741b8cd7, 0xeb31d82e], ['Q', 0x814141ab, 0xd5828281],
];
function table(poly, reflected) {
  const t = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = reflected ? i : (i << 24) >>> 0;
    for (let k = 0; k < 8; k++) c = reflected ? ((c >>> 1) ^ ((c & 1) ? poly : 0)) >>> 0
      : ((c << 1) ^ ((c & 0x80000000) ? poly : 0)) >>> 0;
    t[i] = c;
  }
  return t;
}
function crc(b, t, reflected, init) {
  let c = init >>> 0;
  if (reflected) for (const v of b) c = ((c >>> 8) ^ t[(c ^ v) & 255]) >>> 0;
  else for (const v of b) c = ((c << 8) ^ t[((c >>> 24) ^ v) & 255]) >>> 0;
  return c >>> 0;
}
function reverse(c) {
  let r = 0;
  for (let i = 0; i < 32; i++) { r = ((r << 1) | (c & 1)) >>> 0; c >>>= 1; }
  return r;
}
function adler(b, init) {
  let a = init, z = 0;
  for (const v of b) { a = (a + v) % 65521; z = (z + a) % 65521; }
  return ((z << 16) | a) >>> 0;
}
const crcSpecs = [];
for (const [name, normal, refl] of specs) for (const reflected of [false, true])
  crcSpecs.push({name, reflected, table: table(reflected ? refl : normal, reflected)});
// 标准已知答案，避免扫描器的 CRC 位序实现自洽但错误。
const check = Buffer.from('123456789');
must(((crc(check, table(0xedb88320, true), true, 0xffffffff) ^ 0xffffffff) >>> 0) === 0xcbf43926, 'IEEE CRC 自检失败');
must(((crc(check, table(0x82f63b78, true), true, 0xffffffff) ^ 0xffffffff) >>> 0) === 0xe3069283, 'CRC32C 自检失败');
must(crc(check, table(0x04c11db7, false), false, 0xffffffff) === 0x0376e6e7, 'MPEG2 CRC 自检失败');
const versions = [
  ['3-1', '97dfa394efc91f8643c3b1a0673be2dd96590754b29080ce60d3498ebe3d15be'],
  ['3-2', '92b3f1fda39e37351432d19d0167879f477eb71713a8fbc94b3ba2141ca404e4'],
];
const rows = [];
const referenceRows = JSON.parse(fs.readFileSync(path.join(root, 'reports/reference-decode-results.json'), 'utf8')).results;
for (const [version, expected] of versions) {
  const raw = fs.readFileSync(path.join(root, `data/input/body-${version}-cn/firmware.bin`));
  must(sha(raw) === expected, '官方输入哈希不符');
  const length = +raw.subarray(0, 256).toString().match(/LENGTH=(\d+)/)[1];
  const body = raw.subarray(256, 256 + length);
  const target = body.readUInt32LE(0x17a0), zero = Buffer.from(body);
  zero.writeUInt32LE(0, 0x17a0);
  const ranges = [
    ['首段全部', body], ['首段排除末尾字', Buffer.concat([body.subarray(0, 0x17a0), body.subarray(0x17a4)])],
    ['首段末尾字置零', zero], ['向量区', body.subarray(0, 0x1000)],
    ['secinfo含末尾字', body.subarray(0x1000, 0x17a4)], ['secinfo排除末尾字', body.subarray(0x1000, 0x17a0)],
    ['secinfo末尾字置零', zero.subarray(0x1000, 0x17a4)],
    ['段表4KB', body.subarray(0x1000, 0x2000)], ['段表4KB末尾字置零', zero.subarray(0x1000, 0x2000)],
    ['前8KB末尾字置零', zero.subarray(0, 0x2000)], ['ROM区全部含填充', body.subarray(0x2000)],
  ];
  const packed = [], plains = [];
  for (const name of ['text', 'rodata', 'data']) {
    const at = body.indexOf(Buffer.from(`.ROM.${name}\0`));
    must(at > 0x1000 && at < 0x17a0, 'ROM 表项缺失');
    const start = body.readUInt32LE(at - 16) - 0x10000000, n = body.readUInt32LE(at - 12);
    const p = body.subarray(start, start + n);
    const plain = fs.readFileSync(path.join(root, `output/reference-decoded/body-${version}-cn/${name}.mapped.candidate.bin`));
    const full = fs.readFileSync(path.join(root, `output/reference-decoded/body-${version}-cn/${name}.full.candidate.bin`));
    const evidence = referenceRows.find(r => r.version === version.replace('-', '.') + '-cn' && r.section === '.' + name);
    must(evidence && evidence.mappedSha256 === sha(plain) && evidence.decodedSha256 === sha(full), '参考明文哈希不符');
    ranges.push([`${name}压缩正文`, p], [`${name}明文映射范围`, plain], [`${name}明文含尾部`, full]);
    packed.push(p); plains.push(plain);
  }
  ranges.push(['三个压缩正文拼接', Buffer.concat(packed)], ['三个明文拼接', Buffer.concat(plains)]);
  const results = [], matches = [];
  let trials = 0;
  for (const [name, b] of ranges) {
    const values = new Map();
    let sum = 0, little = 0, big = 0;
    for (const v of b) sum = (sum + v) >>> 0;
    for (let i = 0; i < b.length; i += 4) {
      for (let k = 0; k < 4 && i + k < b.length; k++) {
        little = (little + ((b[i + k] << (8 * k)) >>> 0)) >>> 0;
        big = (big + ((b[i + k] << (8 * (3 - k))) >>> 0)) >>> 0;
      }
    }
    for (const [key, value] of [['byteSum', sum], ['wordSumLE', little], ['wordSumBE', big]]) {
      values.set(key, value); values.set(key + '/negate', (-value) >>> 0); values.set(key + '/complement', (~value) >>> 0);
    }
    values.set('Adler32/init1', adler(b, 1)); values.set('Adler32/init0', adler(b, 0));
    for (const spec of crcSpecs) for (const init of [0, 0xffffffff]) {
      const c = crc(b, spec.table, spec.reflected, init);
      for (const xor of [0, 0xffffffff]) for (const refout of [false, true]) {
        const v = ((refout ? reverse(c) : c) ^ xor) >>> 0;
        values.set(`CRC32/${spec.name}/refin=${spec.reflected}/init=${init.toString(16)}/xor=${xor.toString(16)}/reverseOut=${refout}`, v);
      }
    }
    for (const [algorithm, value] of values) {
      trials++;
      const swapped = ((value >>> 24) | ((value >>> 8) & 0xff00) | ((value << 8) & 0xff0000) | (value << 24)) >>> 0;
      if (value === target || swapped === target) matches.push({range: name, algorithm, byteSwapped: swapped === target});
    }
    results.push({range: name, bytes: b.length, sha256: sha(b), byteSum: sum, wordSumLE: little, wordSumBE: big});
  }
  rows.push({version: version.replace('-', '.') + '-cn', inputSha256: expected,
    targetOffset: '0x17a0', target: '0x' + target.toString(16), trialsIncludingEndian: trials * 2,
    ranges: results, matches});
  console.log(`${version}: ${trials * 2} comparisons, ${matches.length} matches`);
}
const result = {qualification: '有限算法/范围扫描，未匹配不等于证明不是校验值；不连接设备',
  algorithms: 'IEEE/Castagnoli/Koopman/Q；正向及反射；初值0/ffffffff；异或0/ffffffff；输出反射与字节序；字节和/32位字和/补码/反码/Adler32',
  knownAnswerTests: 3, versions: rows, identified: rows.every(r => r.matches.length > 0)};
fs.writeFileSync(path.join(root, 'reports/secinfo-checksum-results-2026-10-27.json'), JSON.stringify(result, null, 2) + '\n');
