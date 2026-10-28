'use strict';

/*
 * Offline codec audit for the YI M1 firmware tools.
 *
 * This driver only CALLS the existing upstream lzss implementation. It does not
 * contain or patch a compression/decompression algorithm, does not repack or
 * flip regions, and does not touch any device or input firmware. It writes only
 * reports/codec-check-results.json.
 *
 * The checks separate three things that the upstream `test` command conflates:
 *   1. tester bookkeeping (lookup arrays and a 1:1 token assumption),
 *   2. decompressor overlap/termination behaviour,
 *   3. compressor match validity and partial-group padding.
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const root = path.resolve(__dirname, '..');
const upstream = path.join(root, 'vendor/yi-mirrorless-firmware-tools');
const lzssPath = path.join(upstream, 'lzss.js');
const firmwarePath = path.join(upstream, 'firmware.js');
const lzss = require(lzssPath);

const RING_SIZE = 0x1000;
const RING_INITIAL = RING_SIZE - 18; // LOOKUP_BUFFER_SIZE - LOOKUP_MAX_LENGTH
const BLOCK = 2048;

const sha256 = data => crypto.createHash('sha256').update(data).digest('hex');

function captureIO(fn) {
  const logs = [];
  const oldLog = console.log;
  const oldWrite = process.stdout.write;
  console.log = (...args) => { logs.push(args.map(String).join(' ')); };
  process.stdout.write = chunk => { logs.push(String(chunk)); return true; };
  try {
    return { value: fn(), logs };
  } finally {
    console.log = oldLog;
    process.stdout.write = oldWrite;
  }
}

function quiet(fn) {
  return captureIO(fn).value;
}

function tokenStats(out, tokens, isInput) {
  const n = tokens.length / 5;
  let overlaps = 0, overrunBytes = 0, mismatchTokens = 0, mismatchBytes = 0;
  let nonOverlapSourceMismatch = 0, distanceZero = 0;
  const examples = [];
  const data = out;
  for (let t = 0; t < n; t++) {
    const inOff = tokens[t * 5];
    const outOff = tokens[t * 5 + 1];
    const index = tokens[t * 5 + 2];
    const length = tokens[t * 5 + 3];
    const ringIndex = tokens[t * 5 + 4];
    const distance = ((ringIndex - index) % RING_SIZE + RING_SIZE) % RING_SIZE;
    if (distance === 0) distanceZero++;
    if (length > distance) {
      overlaps++;
      overrunBytes += length - distance;
      let bad = 0;
      if (distance === 0) {
        bad = length;
      } else {
        for (let k = distance; k < length; k++) {
          // Correct sequential LZSS copy: a byte written earlier in this same
          // match is a legal source (overlap/run).
          const expected = data[outOff + (k % distance)];
          const actual = data[outOff + k];
          if (expected !== actual) bad++;
        }
      }
      if (bad > 0) {
        mismatchTokens++;
        mismatchBytes += bad;
        if (examples.length < 3) {
          const expectedHex = Buffer.from(Array.from({ length }, (_, k) =>
            data[outOff + (distance === 0 ? k : k % distance)])).toString('hex');
          examples.push({
            token: t, compressedOffset: inOff, outputOffset: outOff,
            index, length, ringIndex, distance, badBytes: bad,
            observedHex: Buffer.from(Array.from({ length }, (_, k) => data[outOff + k])).toString('hex'),
            sequentialCopyHex: expectedHex,
          });
        }
      }
    } else {
      for (let k = 0; k < length; k++) {
        const src = outOff - distance + k;
        if (src < 0 || src >= data.length || data[src] !== data[outOff + k]) {
          nonOverlapSourceMismatch++;
          break;
        }
      }
    }
  }
  return {
    tokens: n, overlaps, overrunBytes, mismatchTokens, mismatchBytes,
    nonOverlapSourceMismatch, distanceZero, examples,
    source: isInput ? 'input' : 'decoded output',
  };
}

function walkStream(stream) {
  let pos = 0, out = 0, groups = 0, last = null, stop = null, error = null;
  while (pos < stream.length) {
    const flagPos = pos;
    const flag = stream[pos++];
    if (flag === 0) {
      let zeroCount = 0;
      for (let i = 0; i < 16; i++) {
        if (stream[pos + i] === 0) zeroCount++;
        else break;
      }
      if (zeroCount === 16) {
        stop = { flagOffset: flagPos, next16: stream.subarray(flagPos + 1, flagPos + 17).toString('hex') };
        break;
      }
    }
    const startOut = out;
    const flags = [];
    try {
      for (let bit = 0; bit < 8; bit++) {
        const copy = ((flag >> bit) & 1) === 1;
        flags.push(copy ? 'C' : 'L');
        if (copy) {
          stream[pos++];
          out++;
        } else {
          const l1 = stream[pos++];
          const l2 = stream[pos++];
          if (l1 === undefined || l2 === undefined) throw new Error('truncated lookup');
          out += (l2 & 0x0f) + 3;
        }
      }
    } catch (e) {
      error = String(e);
      break;
    }
    groups++;
    last = { flagOffset: flagPos, flag, flags: flags.join(''), startOut, endOut: out };
  }
  return { bytes: stream.length, stop, groups, outputBytes: out, last, error };
}

function analyzeDecompression(streamFile, decompressedFile) {
  const stream = fs.readFileSync(streamFile);
  const tokens = [];
  const captured = captureIO(() => lzss.decompress(stream, {
    lookupCallback: d => { tokens.push(d[0], d[1], d[2], d[3], d[4]); },
  }));
  const out = captured.value;
  const walk = walkStream(stream);
  const stats = tokenStats(out, tokens);
  const existing = fs.existsSync(decompressedFile) ? fs.readFileSync(decompressedFile) : null;
  let tail = null;
  if (walk.stop) {
    const F = walk.stop.flagOffset;
    let nonZeroAfter = 0;
    for (let i = F; i < stream.length; i++) if (stream[i] !== 0) nonZeroAfter++;
    tail = {
      flagOffset: F,
      streamBytes: stream.length,
      bytesFromFlagToEnd: stream.length - F,
      nonZeroAfterFlag: nonZeroAfter,
      allZeroAfterFlag: nonZeroAfter === 0,
      flagOffsetModBlock: F % BLOCK,
      bytesToBlockBoundary: (BLOCK - (F % BLOCK)) % BLOCK,
      flagByte: stream[F],
      next16: walk.stop.next16,
      finalRealGroup: walk.last,
      padMatchesBlockBoundary: (BLOCK - (F % BLOCK)) % BLOCK === stream.length - F,
    };
  }
  return {
    streamFile: path.relative(root, streamFile),
    streamBytes: stream.length,
    streamSha256: sha256(stream),
    outputBytes: out.length,
    outputSha256: sha256(out),
    decoderOutMatchesWalkOut: walk.outputBytes === out.length,
    decoderLog: captured.logs.filter(l => /end detected/i.test(l)),
    walk,
    tail,
    stats,
    existing: existing ? {
      file: path.relative(root, decompressedFile),
      bytes: existing.length,
      sha256: sha256(existing),
      sameAsThisRun: existing.equals(out),
    } : null,
  };
}

function analyzeCompression(inputFile, label) {
  const input = fs.readFileSync(inputFile);
  const tokens = [];
  const captured = captureIO(() => lzss.compress(input, {
    lookupCallback: d => { tokens.push(d[0], d[1], d[2], d[3], d[4]); },
  }));
  const compressed = captured.value;
  const decCaptured = captureIO(() => lzss.decompress(compressed));
  const decoded = decCaptured.value;
  let prefix = 0;
  while (prefix < input.length && input[prefix] === decoded[prefix]) prefix++;
  const extra = decoded.subarray(input.length);
  const stats = tokenStats(input, tokens, true);
  const walk = walkStream(compressed);
  return {
    label,
    inputFile: path.relative(root, inputFile),
    inputBytes: input.length,
    inputSha256: sha256(input),
    compressedBytes: compressed.length,
    compressedSha256: sha256(compressed),
    compressedNextBlockPadding: (BLOCK - (compressed.length % BLOCK)) % BLOCK,
    tokens: tokens.length / 5,
    overlaps: stats.overlaps,
    invalidOverlaps: stats.mismatchTokens,
    invalidOverlapBytes: stats.mismatchBytes,
    distanceZero: stats.distanceZero,
    examples: stats.examples,
    dcd: {
      decodedBytes: decoded.length,
      prefixMatchBytes: prefix,
      fullPrefixMatch: prefix === input.length,
      extraBytes: extra.length,
      extraAllZero: extra.every(b => b === 0),
      stopDetected: decCaptured.logs.some(l => /end detected/i.test(l)),
    },
    walk,
    compressLog: captured.logs.filter(l => /early end detected/i.test(l)),
  };
}

// ---------------------------------------------------------------------------
// Input identity checks (read-only).
// ---------------------------------------------------------------------------
const expectedInputs = {
  '3.2-cn': {
    file: 'data/input/body-3-2-cn/firmware.bin',
    sha256: '92b3f1fda39e37351432d19d0167879f477eb71713a8fbc94b3ba2141ca404e4',
  },
  '3.1-cn': {
    file: 'data/input/body-3-1-cn/firmware.bin',
    sha256: '97dfa394efc91f8643c3b1a0673be2dd96590754b29080ce60d3498ebe3d15be',
  },
};
const inputs = {};
for (const [version, spec] of Object.entries(expectedInputs)) {
  const data = fs.readFileSync(path.join(root, spec.file));
  const got = sha256(data);
  if (got !== spec.sha256) throw new Error(`input hash mismatch for ${version}: ${got}`);
  const dir = version === '3.2-cn' ? 'body-3-2-cn' : 'body-3-1-cn';
  const analysisFile = path.join(root, 'output', dir, `m1-${version}.analysis.bin`);
  const analysis = fs.readFileSync(analysisFile);
  if (!analysis.equals(data)) throw new Error(`analysis copy differs from input for ${version}`);
  const section0File = path.join(root, 'output', dir, `m1-${version}.analysis.bin.0`);
  const section0 = fs.readFileSync(section0File);
  const section0BodyOffset = 0x100;
  const section0Length = 7370752;
  if (section0.length !== section0Length) throw new Error(`section 0 length mismatch for ${version}`);
  if (!analysis.subarray(section0BodyOffset, section0BodyOffset + section0Length).equals(section0)) {
    throw new Error(`section 0 is not a slice of the analysis copy for ${version}`);
  }
  const subsectionLayout = [
    [0, 4096, '00000000'],
    [4096, 4096, '00004096'],
    [8192, 3119104, '00008192'],
    [3127296, 4124672, '03127296'],
    [7251968, 118784, '07251968'],
  ];
  const subsections = [];
  let cursor = 0;
  for (const [offset, length, suffix] of subsectionLayout) {
    if (offset !== cursor) throw new Error(`subsection gap for ${version} at ${offset}`);
    cursor = offset + length;
    const file = path.join(root, 'output', dir, `m1-${version}.analysis.bin.0.${suffix}`);
    const actual = fs.readFileSync(file);
    const expected = section0.subarray(offset, offset + length);
    if (!actual.equals(expected)) throw new Error(`subsection ${suffix} differs from section 0 slice for ${version}`);
    subsections.push({ suffix, offset, bytes: actual.length, sameAsSection0Slice: true });
  }
  if (cursor !== section0Length) throw new Error(`subsection layout does not cover section 0 for ${version}`);
  inputs[version] = {
    file: spec.file, bytes: data.length, sha256: got,
    analysisCopy: { file: path.relative(root, analysisFile), bytes: analysis.length, sha256: sha256(analysis), sameAsInput: true },
    section0: { file: path.relative(root, section0File), bytes: section0.length, sha256: sha256(section0), sameAsInputSection0Slice: true, subsections },
  };
}

// ---------------------------------------------------------------------------
// 1. Small vectors: compress -> decompress, padding and length behaviour.
// ---------------------------------------------------------------------------
const random1024 = (() => {
  let s = 12345;
  const b = Buffer.alloc(1024);
  for (let i = 0; i < b.length; i++) {
    s = (s * 1103515245 + 12345) >>> 0;
    b[i] = (s >>> 16) & 0xff;
  }
  return b;
})();

const vectorInputs = [
  ['empty', Buffer.alloc(0)],
  ['1 literal', Buffer.from('A')],
  ['7 literals', Buffer.from('ABCDEFG')],
  ['8 literals', Buffer.from('ABCDEFGH')],
  ['9 literals', Buffer.from('ABCDEFGHI')],
  ['periodic 3x20', Buffer.from('ABC'.repeat(20))],
  ['zeros 100', Buffer.alloc(100)],
  ['sequence 0..254', Buffer.from(Array.from({ length: 255 }, (_, i) => i))],
  ['random 1024', random1024],
];
const vectors = vectorInputs.map(([name, input]) => {
  let compressed;
  let error = null;
  try {
    compressed = quiet(() => lzss.compress(input));
  } catch (e) {
    error = String(e);
  }
  if (error !== null) {
    return { name, inputBytes: input.length, error, note: 'lzss.compress allocates input.length*2 bytes; sub-5-byte inputs can exceed it.' };
  }
  const decoded = quiet(() => lzss.decompress(compressed));
  let prefix = 0;
  while (prefix < input.length && input[prefix] === decoded[prefix]) prefix++;
  const extra = decoded.subarray(input.length);
  return {
    name, inputBytes: input.length, compressedBytes: compressed.length,
    decodedBytes: decoded.length, prefixMatchBytes: prefix,
    extraBytes: extra.length, extraAllZero: extra.every(b => b === 0),
  };
});

// ---------------------------------------------------------------------------
// 2. Synthetic overlap vectors. These are hand-assembled valid LZSS streams,
//    not generated by a new codec. They isolate the sequential-copy rule.
// ---------------------------------------------------------------------------
const warmupStream = Buffer.concat([
  Buffer.from([0xff]), Buffer.from('WXYZABCD'),
  Buffer.from([0xfe]), Buffer.from([0xf2, 0xf5]), Buffer.from('QQQQQQQ'),
]); // lookup index 4082, length 8, distance 4
const warmupExpected = Buffer.from('WXYZABCD' + 'ABCDABCD' + 'QQQQQQQ');
const warmupOut = quiet(() => lzss.decompress(warmupStream));
let warmupDiff = -1;
for (let i = 0; i < Math.max(warmupOut.length, warmupExpected.length); i++) {
  if (warmupOut[i] !== warmupExpected[i]) { warmupDiff = i; break; }
}

const steadyFill = Buffer.alloc(4096, 0x41); // A
steadyFill[4095] = 0x42; // B
const steadyParts = [];
for (let i = 0; i < 512; i++) {
  steadyParts.push(Buffer.from([0xff]), steadyFill.subarray(i * 8, (i + 1) * 8));
}
steadyParts.push(Buffer.from([0xfe]), Buffer.from([0xed, 0xff]), Buffer.from('QQQQQQQ'));
const steadyStream = Buffer.concat(steadyParts); // lookup index 4077, length 18, distance 1
const steadyExpected = Buffer.concat([steadyFill, Buffer.alloc(18, 0x42), Buffer.from('QQQQQQQ')]);
const steadyOut = quiet(() => lzss.decompress(steadyStream));
let steadyDiff = -1;
for (let i = 0; i < Math.max(steadyOut.length, steadyExpected.length); i++) {
  if (steadyOut[i] !== steadyExpected[i]) { steadyDiff = i; break; }
}

// A valid-looking 8-lookup group whose 16 data bytes are all zero is
// indistinguishable from the end padding under the upstream heuristic.
const zeroParts = [];
for (let i = 0; i < 512; i++) zeroParts.push(Buffer.from([0xff]), Buffer.alloc(8));
zeroParts.push(Buffer.from([0x00]), Buffer.alloc(16));
const zeroStream = Buffer.concat(zeroParts);
const zeroOut = quiet(() => lzss.decompress(zeroStream));
const zeroWalk = walkStream(zeroStream);

const synthetic = {
  warmupOverlap: {
    streamBytes: warmupStream.length,
    index: 4082, length: 8, distance: 4,
    outputBytes: warmupOut.length,
    expectedBytes: warmupExpected.length,
    firstDiff: warmupDiff,
    observedHex: warmupOut.subarray(Math.max(0, warmupDiff - 4), warmupDiff + 12).toString('hex'),
    sequentialCopyHex: warmupExpected.subarray(Math.max(0, warmupDiff - 4), warmupDiff + 12).toString('hex'),
  },
  steadyStateOverlap: {
    streamBytes: steadyStream.length,
    index: 4077, length: 18, distance: 1,
    outputBytes: steadyOut.length,
    expectedBytes: steadyExpected.length,
    firstDiff: steadyDiff,
    observedHex: steadyOut.subarray(Math.max(0, steadyDiff - 4), steadyDiff + 12).toString('hex'),
    sequentialCopyHex: steadyExpected.subarray(Math.max(0, steadyDiff - 4), steadyDiff + 12).toString('hex'),
  },
  terminationFalsePositive: {
    streamBytes: zeroStream.length,
    flagOffset: zeroWalk.stop ? zeroWalk.stop.flagOffset : null,
    outputBytes: zeroOut.length,
    ifDecodedAsEight3ByteLookups: 4096 + 8 * 3,
    stoppedEarly: zeroOut.length === 4096,
    note: 'Synthetic only; the actual 3.1/3.2 tails are all zero and terminate at the expected padding.',
  },
};

// ---------------------------------------------------------------------------
// 3. Compressor counterexample: upstream roundtrip passes, sequential decoder
//    would not. This proves the compressor can emit invalid overlapping matches.
// ---------------------------------------------------------------------------
const counterInput = Buffer.from('WXYZABCABCWXYZ');
const counterTokens = [];
const counterCompressed = quiet(() => lzss.compress(counterInput, {
  lookupCallback: d => counterTokens.push(d.slice()),
}));
const counterDecoded = quiet(() => lzss.decompress(counterCompressed));
let counterPrefix = 0;
while (counterPrefix < counterInput.length && counterInput[counterPrefix] === counterDecoded[counterPrefix]) counterPrefix++;
let counterToken = null;
for (const [pos, inOff, index, length, ringIndex] of counterTokens) {
  const distance = ((ringIndex - index) % RING_SIZE + RING_SIZE) % RING_SIZE;
  if (length > distance) {
    let bad = 0;
    for (let k = distance; k < length; k++) {
      if (counterInput[inOff + k] !== counterInput[inOff + (k % distance)]) bad++;
    }
    counterToken = { pos, inOff, index, length, ringIndex, distance, badBytes: bad };
    counterToken.inputHex = counterInput.subarray(inOff, inOff + length).toString('hex');
    counterToken.sequentialCopy = Buffer.from(Array.from({ length }, (_, k) =>
      counterInput[inOff + (k % distance)])).toString('hex');
    break;
  }
}
const counterCorrect = counterToken
  ? Buffer.concat([
    counterInput.subarray(0, counterToken.inOff),
    Buffer.from(counterToken.sequentialCopy, 'hex'),
    counterInput.subarray(counterToken.inOff + counterToken.length),
  ])
  : null;
let counterCorrectDiff = -1;
if (counterCorrect) {
  for (let i = 0; i < counterInput.length; i++) {
    if (counterInput[i] !== counterCorrect[i]) { counterCorrectDiff = i; break; }
  }
}
const compressorCounterexample = {
  input: counterInput.toString('ascii'),
  compressedBytes: counterCompressed.length,
  upstreamDcdPrefixMatch: counterPrefix,
  upstreamDcdFullPrefix: counterPrefix === counterInput.length,
  token: counterToken,
  sequentialCorrectOutput: counterCorrect ? counterCorrect.toString('ascii') : null,
  firstDifferenceFromInput: counterCorrectDiff,
  note: 'Upstream DCD succeeds because the same buggy overlap rule is used in both directions.',
};

// ---------------------------------------------------------------------------
// 4. Actual offline subsections: decompression audit for 3.2-cn and 3.1-cn.
// ---------------------------------------------------------------------------
const decompression = [];
for (const version of ['3.2-cn', '3.1-cn']) {
  const dir = version === '3.2-cn' ? 'body-3-2-cn' : 'body-3-1-cn';
  const prefix = version === '3.2-cn' ? 'm1-3.2-cn.analysis.bin.0.' : 'm1-3.1-cn.analysis.bin.0.';
  for (const offset of ['00008192', '03127296', '07251968']) {
    decompression.push(analyzeDecompression(
      path.join(root, 'output', dir, prefix + offset),
      path.join(root, 'output', dir, prefix + offset + '.decompressed'),
    ));
  }
}

// ---------------------------------------------------------------------------
// 5. Actual offline subsections: full compress -> decompress audit (3.2-cn).
//    The input is the existing upstream-decoded artifact, explicitly labelled.
// ---------------------------------------------------------------------------
const roundtrips = [];
for (const offset of ['00008192', '03127296', '07251968']) {
  const inputFile = path.join(root, 'output', 'body-3-2-cn',
    'm1-3.2-cn.analysis.bin.0.' + offset + '.decompressed');
  roundtrips.push(analyzeCompression(inputFile, '3.2-cn subsection ' + offset));
}

// ---------------------------------------------------------------------------
// 6. Tester bookkeeping: counts, the undefined index, and the first logged
//    "mismatch" (which is a legitimate alternative tokenization).
// ---------------------------------------------------------------------------
const decompByOffset = {};
for (const d of decompression) {
  const m = /\.0\.(\d{8})$/.exec(d.streamFile);
  if (m && d.streamFile.includes('3-2-cn')) decompByOffset[m[1]] = d;
}

const tester = { mismatchLines: 0, firstLoggedMismatch: null, undefinedEvidence: [] };
const logPath = path.join(root, 'logs', 'codec-roundtrip.txt');
if (fs.existsSync(logPath)) {
  const logText = fs.readFileSync(logPath, 'utf8');
  const lines = logText.split(/\r?\n/);
  const mismatchRe = /lookup mismatch: (\d+),(\d+),(\d+),(\d+),(\d+) <-> (\d+),(\d+),(\d+),(\d+),(\d+)/;
  let first = null;
  for (const line of lines) {
    if (line.includes('lookup mismatch')) tester.mismatchLines++;
    const m = mismatchRe.exec(line);
    if (m && !first) first = m.slice(1).map(Number);
  }
  if (first) {
    const [in1, out1, idx1, len1, ring1, in2, out2, idx2, len2, ring2] = first;
    const decoded = quiet(() => lzss.decompress(fs.readFileSync(path.join(root,
      'output/body-3-2-cn/m1-3.2-cn.analysis.bin.0.00008192'))));
    const sourcePos = idx => ((idx - RING_INITIAL) % RING_SIZE + RING_SIZE) % RING_SIZE;
    const source = (idx, len) => {
      const p = sourcePos(idx);
      return decoded.subarray(p, p + len);
    };
    const target = decoded.subarray(out1, out1 + len1);
    tester.firstLoggedMismatch = {
      raw: first,
      decompression: { compressedOffset: in1, outputOffset: out1, index: idx1, length: len1, ringIndex: ring1 },
      compression: { compressedOffset: in2, outputOffset: out2, index: idx2, length: len2, ringIndex: ring2 },
      decompressionSourceHex: source(idx1, len1).toString('hex'),
      compressionSourceHex: source(idx2, len2).toString('hex'),
      targetHex: target.toString('hex'),
      bothSourcesMatchTarget: source(idx1, len1).equals(target) && source(idx2, len2).equals(target),
    };
  }
}

for (const r of roundtrips) {
  const offset = r.inputFile.match(/\.0\.(\d{8})\.decompressed$/)[1];
  const d = decompByOffset[offset];
  if (!d) continue;
  const M = d.stats.tokens;
  const N = r.tokens;
  let simulatedError = null;
  if (N > M) {
    try {
      const arr = new Array(M);
      arr[N - 1].every(() => true);
    } catch (e) {
      simulatedError = `${e.name}: ${e.message}`;
    }
  }
  tester.undefinedEvidence.push({
    subsection: offset,
    decompressionLookups: M,
    compressionLookups: N,
    compressionMinusDecompression: N - M,
    firstLookupWithoutDecompressionCounterpart: N > M ? M : null,
    simulatedError,
    note: N > M ? 'firmware.js line 418 indexes decompressionLookups with the compression token ordinal; the extra tokens make l1 undefined.' : 'No extra compression token in this subsection.',
  });
}

// ---------------------------------------------------------------------------
// 7. Environment and output.
// ---------------------------------------------------------------------------
let stringVersion = null;
try {
  stringVersion = JSON.parse(fs.readFileSync(path.join(upstream, 'node_modules/string/package.json'), 'utf8')).version;
} catch (e) { stringVersion = 'unreadable'; }

const results = {
  generatedAt: new Date().toISOString(),
  environment: {
    node: process.version,
    platform: process.platform,
    cwd: root,
    upstreamCommit: 'b90b96c124a3b076fa0283404e6595a4a40d20d0',
    lzss: { file: path.relative(root, lzssPath), bytes: fs.statSync(lzssPath).size, sha256: sha256(fs.readFileSync(lzssPath)) },
    firmware: { file: path.relative(root, firmwarePath), bytes: fs.statSync(firmwarePath).size, sha256: sha256(fs.readFileSync(firmwarePath)) },
    stringVersion,
  },
  inputs,
  summary: {
    testerDefect: 'The TypeError is a test-bookkeeping failure: compression emits more lookups than decompression, so l1 is undefined at firmware.js:418.',
    decompressorDefect: 'Conditional on sequential overlap-copy semantics: the upstream decoder pre-reads a whole lookup before appending it, so output can differ from per-byte feedback. Camera semantics have not yet been independently established.',
    compressorDefect: 'Conditional on sequential overlap-copy semantics: the compressor can emit matches inconsistent with that reference yet self-roundtrip with the same implementation. This does not establish compatibility with the camera.',
    padding: 'The compressor pads the final flag group with literal zeros. The compressed stream itself has no length field, but the outer load/section table contains section lengths. DCD can append 0..7 zeros; boundary handling requires independent validation.',
    termination: 'The decoder stops at flag 0x00 followed by 16 zero bytes. Actual 3.1/3.2 compressed subsections end at all-zero 2048-block padding, but the rule is heuristic, not an explicit length.',
    camera: 'No camera, flash, repack, or region flip was performed. A successful upstream round-trip does not establish camera-compatible compressed bytes.',
  },
  vectors,
  synthetic,
  compressorCounterexample,
  decompression,
  roundtrips,
  tester,
  boundaries: [
    'Offline only: no camera/device access, no E: access, no writes to data/input or external-downloads, no firmware byte changes, no repack/flipRegion, no C: writes, no global dependency installs.',
    'Only the existing upstream lzss compressor/decompressor are executed; this driver contains no replacement codec.',
    'The full-subsection recompression inputs are the existing output/*.decompressed artifacts, which are themselves affected by the decoder defect. The measurements therefore describe the current pipeline, not a corrected image.',
    'No independently validated corrected image was produced. Overlap difference counts are conditional comparisons with sequential-copy semantics, not proven corruption counts for factory firmware.',
    'No conclusion is made about whether any modified firmware would boot, pass signature checks, or be safe to flash.',
  ],
};

const outFile = path.join(root, 'reports', 'codec-check-results.json');
fs.writeFileSync(outFile, JSON.stringify(results, null, 2) + '\n');

// Concise human-readable log.
console.log('YI M1 codec audit (offline; upstream lzss only)');
console.log(`node ${process.version}; string@${stringVersion}`);
console.log(`lzss.js sha256 ${results.environment.lzss.sha256}`);
console.log(`3.2-cn input sha256 ${inputs['3.2-cn'].sha256}`);
console.log(`3.1-cn input sha256 ${inputs['3.1-cn'].sha256}`);
console.log('\nSmall vectors (compress -> decompress):');
for (const v of vectors) {
  if (v.error) {
    console.log(`  ${v.name.padEnd(18)} in=${v.inputBytes} ERROR=${v.error}`);
  } else {
    console.log(`  ${v.name.padEnd(18)} in=${v.inputBytes} comp=${v.compressedBytes} dec=${v.decodedBytes} prefix=${v.prefixMatchBytes} extra=${v.extraBytes}${v.extraAllZero ? ' (zero)' : ' (NONZERO)'}`);
  }
}
console.log('\nSynthetic overlap vectors:');
console.log(`  warmup: index=4082 len=8 dist=4 firstDiff=${synthetic.warmupOverlap.firstDiff} (observed ${synthetic.warmupOverlap.observedHex} vs sequential ${synthetic.warmupOverlap.sequentialCopyHex})`);
console.log(`  steady: index=4077 len=18 dist=1 firstDiff=${synthetic.steadyStateOverlap.firstDiff} (observed ${synthetic.steadyStateOverlap.observedHex} vs sequential ${synthetic.steadyStateOverlap.sequentialCopyHex})`);
console.log(`  termination false-positive: output=${synthetic.terminationFalsePositive.outputBytes}, would-be=${synthetic.terminationFalsePositive.ifDecodedAsEight3ByteLookups}, stoppedEarly=${synthetic.terminationFalsePositive.stoppedEarly}`);
console.log('\nCompressor counterexample:');
console.log(`  input=${compressorCounterexample.input} upstreamDcdPrefix=${compressorCounterexample.upstreamDcdPrefixMatch}/${Buffer.byteLength(compressorCounterexample.input)} invalidToken=${JSON.stringify(compressorCounterexample.token)}`);
console.log(`  sequential output would be ${compressorCounterexample.sequentialCorrectOutput} (first diff at ${compressorCounterexample.firstDifferenceFromInput})`);
console.log('\nActual decompression (3.2-cn / 3.1-cn):');
for (const d of decompression) {
  const s = d.stats;
  console.log(`  ${d.streamFile} in=${d.streamBytes} out=${d.outputBytes} tokens=${s.tokens} overlaps=${s.overlaps} badTokens=${s.mismatchTokens} badBytes>=${s.mismatchBytes} nonOverlapBad=${s.nonOverlapSourceMismatch} tailZero=${d.tail ? d.tail.allZeroAfterFlag : 'n/a'} padOK=${d.tail ? d.tail.padMatchesBlockBoundary : 'n/a'} sameArtifact=${d.existing ? d.existing.sameAsThisRun : 'n/a'}`);
}
console.log('\nFull recompression / DCD (3.2-cn):');
for (const r of roundtrips) {
  console.log(`  ${r.label}: in=${r.inputBytes} comp=${r.compressedBytes} tokens=${r.tokens} overlaps=${r.overlaps} invalid=${r.invalidOverlaps} invalidBytes=${r.invalidOverlapBytes} dcdPrefix=${r.dcd.prefixMatchBytes}/${r.inputBytes} extra=${r.dcd.extraBytes}${r.dcd.extraAllZero ? ' zero' : ' NONZERO'}`);
}
console.log('\nTester:');
console.log(`  logged mismatch lines=${tester.mismatchLines}`);
console.log(`  first logged mismatch bothSourcesMatchTarget=${tester.firstLoggedMismatch ? tester.firstLoggedMismatch.bothSourcesMatchTarget : 'n/a'} ${tester.firstLoggedMismatch ? JSON.stringify(tester.firstLoggedMismatch.raw) : ''}`);
for (const e of tester.undefinedEvidence) {
  console.log(`  sub ${e.subsection}: decompLookups=${e.decompressionLookups} compLookups=${e.compressionLookups} extra=${e.compressionMinusDecompression} simulated=${e.simulatedError}`);
}
console.log(`\nWrote ${path.relative(root, outFile)}`);
console.log('No repack, no region flip, no device access, no firmware modification.'); 
