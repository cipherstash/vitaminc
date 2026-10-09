const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const addon = require(path.resolve(process.argv[2]));
const corpus = JSON.parse(fs.readFileSync(path.join(__dirname, '../../../testdata/value-conformance.json')));
function expected(row) {
  if (/^(u?int)/.test(row.kind)) return BigInt(row.value);
  switch (row.kind) {
    case 'undefined': return undefined;
    case 'bytes': return Buffer.from(row.value, 'hex');
    case 'date': return {date: row.value};
    case 'decimal': return {decimal: row.value};
    case 'timestamp': return row.js_date ? new Date(row.value) : {timestamp: row.value};
    default: return row.value;
  }
}
for (const row of corpus.vectors) {
  const wire = Buffer.from(row.transport, 'hex');
  assert.equal(addon.codecRoundTrip(wire).toString('hex'), row.transport, row.name);
  const value = addon.decode(wire);
  assert.deepEqual(value, expected(row), row.name);
  assert.equal(addon.encode(value).toString('hex'), row.js_reencode ?? row.transport, row.name);
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
for (const decimal of ['NaN','Infinity','-Infinity','+inf',NaN,Infinity,-Infinity]) assert.throws(() => addon.encode({decimal}), {name:'TypeError',code:'ERR_NON_FINITE_DECIMAL'});
assert.throws(() => addon.encode({decimal:'79228162514264337593543950336'}), {code:'ERR_INVALID_DECIMAL'});
assert.throws(() => addon.encode({date:'2023-02-29'}), {code:'ERR_INVALID_DATE'});
assert.throws(() => addon.encode(new Date(NaN)), {code:'ERR_INVALID_TIMESTAMP'});
assert.deepEqual(addon.decode(addon.encode(new Date(-1))), new Date(-1));
const nested = {items:[1n, {date:'2024-02-29'}, {decimal:'1.50'}, new Date(0)]};
assert.deepEqual(addon.decode(addon.encode(nested)), nested);
assert.throws(() => addon.encode(new Map([['a',1]])));
assert.throws(() => addon.encode([,1]));
assert.throws(() => addon.encode('\ud800'));
// Non-string wrapper payloads keep the wrapper's typed error code.
for (const [input, code] of [
  [{date: new Date(0)}, 'ERR_INVALID_DATE'],
  [{date: {y: 2024}}, 'ERR_INVALID_DATE'],
  [{timestamp: 1700000000000}, 'ERR_INVALID_TIMESTAMP'],
  [{timestamp: null}, 'ERR_INVALID_TIMESTAMP'],
  [{decimal: 1n}, 'ERR_INVALID_DECIMAL'],
  [{decimal: 1.5}, 'ERR_INVALID_DECIMAL'],
]) assert.throws(() => addon.encode(input), {name: 'TypeError', code}, JSON.stringify(Object.keys(input)));
// Expanded-year timestamps decrypt as wrappers and encrypt again unchanged.
for (const timestamp of ['+12000-01-01T00:00:00.000000001Z', '-0005-03-01T12:00:00.000000001Z']) {
  assert.deepEqual(addon.decode(addon.encode({timestamp})), {timestamp});
}
// Reserved wrapper keys: a one-key object from another language reads as a
// wrapper, so this decrypt-then-encrypt is lossy by design (documented).
assert.deepEqual(addon.decode(addon.encode({date: '2024-01-01'})), {date: '2024-01-01'});
assert.throws(() => addon.encode({date: 'tomorrow'}), {code: 'ERR_INVALID_DATE'});
const ordinary = {date:'not a wrapper', extra:true};
assert.deepEqual(addon.decode(addon.encode(ordinary)), ordinary);
console.log(`Node conformance: ${corpus.vectors.length} values, ${corpus.malformed.length} refusals, BigInt boundaries passed`);
