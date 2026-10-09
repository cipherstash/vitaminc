const assert = require('node:assert/strict');
const { copyFileSync, mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join, resolve } = require('node:path');

// Cargo names the cdylib for the platform; Node requires a .node extension.
const directory = mkdtempSync(join(tmpdir(), 'vitaminc-kind-inventory-'));
try {
  const addon = join(directory, 'kind_inventory.node');
  copyFileSync(resolve(process.argv[2]), addon);
  const samples = require(addon);
  assert.deepStrictEqual(samples, {
    bool: true,
    int32: -32n,
    int64: -(1n << 63n),
    uint32: 0xffffffffn,
    uint64: (1n << 64n) - 1n,
    float32: 1.5,
    float64: 2.5,
    string: 'hello',
    bytes: Buffer.from([0, 255]),
    int8: -128n,
    uint8: 255n,
    int16: -32768n,
    uint16: 65535n,
    int128: -(1n << 127n),
    uint128: (1n << 128n) - 1n,
    date: { date: '2024-02-29' },
    timestamp: new Date(0),
    decimal: { decimal: '1.50' },
    array: [true],
    object: { answer: 42n },
    null: null,
    undefined: undefined,
    passthrough: true,
  });
  console.log('Every ValueKind converts to its expected JavaScript value');
} finally {
  rmSync(directory, { recursive: true, force: true });
}
