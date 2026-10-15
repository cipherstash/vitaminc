// Scalar conversions at the N-API boundary against the shared corpus: every
// vector decodes to the JavaScript value of its kind and encodes back to its
// bytes, and the BigInt width rule and the typed error codes hold. Run by
// tests/node.rs with the test addon's path.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const addon = require(path.resolve(process.argv[2]));
const corpus = JSON.parse(fs.readFileSync(path.join(__dirname, '../../../testdata/value-conformance.json')));
const { VcDate, VcTimestamp, VcDecimal, VcUuid } = addon;
function expected(row) {
  if (/^(u?int)/.test(row.kind)) return BigInt(row.value);
  switch (row.kind) {
    case 'undefined': return undefined;
    case 'bytes': return Buffer.from(row.value, 'hex');
    case 'date': return new VcDate(row.value);
    case 'decimal': return new VcDecimal(row.value);
    case 'timestamp': return row.js_date ? new Date(row.value) : new VcTimestamp(row.value);
    default: return row.value;
  }
}
let checked = 0;
for (const row of corpus.vectors) {
  const wire = Buffer.from(row.transport, 'hex');
  if (row.frame === 'refused') {
    // ADR 0001 section 3 refuses this encoding; #414 moves it to `malformed`.
    assert.throws(() => addon.codecRoundTrip(wire), undefined, row.name);
    assert.throws(() => addon.decode(wire), undefined, row.name);
    continue;
  }
  const reencoded = row.frame_reencode ?? row.transport;
  assert.equal(addon.codecRoundTrip(wire).toString('hex'), reencoded, row.name);
  const value = addon.decode(wire);
  if (row.frame_reencode) {
    // The frame codec reads this vector as a different value (ADR 0001
    // section 3); #414 pins what that value is. Until then only the bytes.
    assert.equal(addon.encode(value).toString('hex'), reencoded, row.name);
    continue;
  }
  assert.deepEqual(value, expected(row), row.name);
  // Encode the decoded value and, independently, the expected one.
  for (const input of [value, expected(row)]) {
    assert.equal(addon.encode(input).toString('hex'), row.js_reencode ?? row.transport, row.name);
  }
  checked++;
}
for (const row of corpus.malformed) assert.throws(() => addon.decode(Buffer.from(row.transport, 'hex')), undefined, row.name);
const boundaries = [
  [0n,12], [127n,12], [128n,13], [255n,13], [256n,14], [32767n,14], [32768n,15], [65535n,15], [65536n,4],
  [(1n<<31n)-1n,4], [1n<<31n,6], [(1n<<32n)-1n,6], [1n<<32n,5], [(1n<<63n)-1n,5], [1n<<63n,7],
  [(1n<<64n)-1n,7], [1n<<64n,16], [(1n<<127n)-1n,16], [1n<<127n,17], [(1n<<128n)-1n,17],
  [-128n,12], [-129n,14], [-32768n,14], [-32769n,4], [-(1n<<31n),4], [-(1n<<31n)-1n,5], [-(1n<<63n),5], [-(1n<<63n)-1n,16], [-(1n<<127n),16],
];
for (const [value, tag] of boundaries) {
  const wire = addon.encode(value);
  assert.equal(wire[0], tag);
  assert.equal(addon.decode(wire), value);
}
for (const value of [1n<<128n, -(1n<<127n)-1n]) assert.throws(() => addon.encode(value), {name:'TypeError',code:'ERR_INTEGER_RANGE'});
for (const decimal of ['NaN','Infinity','-Infinity','+inf']) assert.throws(() => addon.encode(new VcDecimal(decimal)), {name:'TypeError',code:'ERR_NON_FINITE_DECIMAL'});
assert.throws(() => addon.encode(new VcDecimal('79228162514264337593543950336')), {code:'ERR_INVALID_DECIMAL'});
assert.throws(() => addon.encode(new VcDate('2023-02-29')), {code:'ERR_INVALID_DATE'});
assert.throws(() => addon.encode(new VcUuid('not-a-uuid')), {code:'ERR_INVALID_UUID'});
assert.throws(() => addon.encode(new Date(NaN)), {code:'ERR_INVALID_TIMESTAMP'});
// A leap second has no count since the epoch and is refused (ADR 0001 section 3).
assert.throws(() => addon.encode(new VcTimestamp('2016-12-31T23:59:60Z')), {code:'ERR_INVALID_TIMESTAMP'});
assert.deepEqual(addon.decode(addon.encode(new Date(-1))), new Date(-1));
// A Date is stored as its millisecond count: Timestamp(Millis) over an i64,
// which has no shorthand tag and so travels in the 0xF3 envelope.
assert.equal(addon.encode(new Date(123)).toString('hex'), 'f30301057b00000000000000');
assert.equal(addon.encode(new Date(-1)).toString('hex'), 'f3030105ffffffffffffffff');
// A UUID is sixteen bytes under its logical type, in the envelope too.
const uuid = new VcUuid('123e4567-e89b-12d3-a456-426614174000');
assert.equal(addon.encode(uuid).toString('hex'), 'f305000b10000000123e4567e89b12d3a456426614174000');
assert.deepEqual(addon.decode(addon.encode(uuid)), uuid);
assert.deepEqual(addon.decode(addon.encode(new VcUuid('123E4567-E89B-12D3-A456-426614174000'))), uuid);
const nested = {items:[1n, new VcDate('2024-02-29'), new VcDecimal('1.50'), new Date(0), uuid]};
assert.deepEqual(addon.decode(addon.encode(nested)), nested);
assert.throws(() => addon.encode(new Map([['a',1]])));
assert.throws(() => addon.encode([,1]));
assert.throws(() => addon.encode('\ud800'));
// A wrapper takes a string and nothing else; the text itself is checked
// when the value is encrypted, so one rule applies however it was made.
for (const Wrapper of [VcDate, VcTimestamp, VcDecimal, VcUuid]) {
  for (const payload of [new Date(0), {y: 2024}, 1700000000000, null, 1n, 1.5, undefined]) {
    assert.throws(() => new Wrapper(payload), {name: 'TypeError'}, Wrapper.name);
  }
}
for (const [Wrapper, code] of [[VcDate, 'ERR_INVALID_DATE'], [VcTimestamp, 'ERR_INVALID_TIMESTAMP'], [VcDecimal, 'ERR_INVALID_DECIMAL'], [VcUuid, 'ERR_INVALID_UUID']]) {
  // An instance made without the constructor has no text.
  assert.throws(() => addon.encode(Object.create(Wrapper.prototype)), {name: 'TypeError', code}, Wrapper.name);
  const forged = Object.create(Wrapper.prototype);
  forged.value = 42;
  assert.throws(() => addon.encode(forged), {name: 'TypeError', code}, Wrapper.name);
}
// Expanded-year timestamps decrypt as wrappers and encrypt again unchanged.
for (const timestamp of ['+12000-01-01T00:00:00.000000001Z', '-0005-03-01T12:00:00.000000001Z']) {
  assert.deepEqual(addon.decode(addon.encode(new VcTimestamp(timestamp))), new VcTimestamp(timestamp));
}
// A whole-millisecond timestamp written by another binding is a Date here;
// a finer one is a VcTimestamp, so no precision is discarded.
assert.deepEqual(addon.decode(Buffer.from('130000000000000000c0d45407', 'hex')), new Date(123));
assert.deepEqual(addon.decode(Buffer.from('13ffffffffffffffffffc99a3b', 'hex')), new VcTimestamp('1969-12-31T23:59:59.999999999Z'));
// A one-key object is ordinary data, whichever language wrote it (#382):
// only a wrapper instance is a wrapper.
for (const ordinary of [{date: '2024-01-01'}, {date: 'tomorrow'}, {timestamp: 1}, {decimal: '1.50'}, {date: 'not a wrapper', extra: true}]) {
  assert.deepEqual(addon.decode(addon.encode(ordinary)), ordinary);
}
// The wrappers hold their text as an own, read-only, enumerable `value`,
// and serialize as that text.
const date = new VcDate('2024-02-29');
assert.equal(date.value, '2024-02-29');
assert.equal(JSON.stringify({date}), '{"date":"2024-02-29"}');
assert.equal(String(date), '2024-02-29');
assert.deepEqual(Object.keys(date), ['value']);
assert.throws(() => { 'use strict'; date.value = 'x'; }, {name: 'TypeError'});
assert.deepEqual(structuredClone(date), {value: '2024-02-29'});
console.log(`Node conformance: ${checked} values, ${corpus.malformed.length} refusals, BigInt boundaries passed`);
