import * as assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import parse from '../parse.js';
import v4ToV7 from '../v4ToV7.js';
import v7 from '../v7.js';
import v7ToV4 from '../v7ToV4.js';
import version from '../version.js';

// Cross-implementation test vector from the uuid47 reference implementation
// README, https://github.com/n2p5/uuid47 (key K0 = 0x0123456789abcdef,
// K1 = 0xfedcba9876543210, little-endian)
const REF_KEY = Uint8Array.of(
  0xef,
  0xcd,
  0xab,
  0x89,
  0x67,
  0x45,
  0x23,
  0x01,
  0x10,
  0x32,
  0x54,
  0x76,
  0x98,
  0xba,
  0xdc,
  0xfe,
);
const REF_V7 = '018f2d9f-9a2a-7def-8c3f-7b1a2c4d5e6f';
const REF_V4 = '2463c780-7fca-4def-8c3f-7b1a2c4d5e6f';

const KEY = Uint8Array.of(
  0x2f,
  0x4a,
  0x91,
  0x77,
  0x05,
  0xe3,
  0xc8,
  0x1b,
  0xd6,
  0x30,
  0xaa,
  0x42,
  0x9e,
  0x5d,
  0x08,
  0xfc,
);

describe('v7ToV4 / v4ToV7', () => {
  test('uuid47 reference vector', () => {
    assert.strictEqual(v7ToV4(REF_V7, REF_KEY), REF_V4);
    assert.strictEqual(v4ToV7(REF_V4, REF_KEY), REF_V7);
  });

  test('key longer than 16 bytes is SHA-256 derived (Symfony-compatible)', () => {
    // Independently computed (Python SipHash-2-4 + hashlib): a secret longer
    // than 16 bytes is hashed with SHA-256 and truncated to 16 bytes, exactly
    // as Symfony's Uuid47Transformer does.
    const secret = new TextEncoder().encode(
      'a-much-longer-than-16-byte-symfony-secret',
    );
    const expectedV4 = '2f02947a-fd0b-4def-8c3f-7b1a2c4d5e6f';

    assert.strictEqual(v7ToV4(REF_V7, secret), expectedV4);
    assert.strictEqual(v4ToV7(expectedV4, secret), REF_V7);
  });

  test('same input and key always produce the same output', () => {
    const id = v7();
    assert.strictEqual(v7ToV4(id, KEY), v7ToV4(id, KEY));
  });

  test('round-trip', () => {
    for (let i = 0; i < 100; i++) {
      const original = v7();
      const facade = v7ToV4(original, KEY);

      assert.strictEqual(version(facade), 4);
      assert.strictEqual(v4ToV7(facade, KEY), original);
    }
  });

  test('only timestamp and version fields change', () => {
    const original = v7();
    const facade = v7ToV4(original, KEY);
    const originalBytes = parse(original);
    const facadeBytes = parse(facade);

    // version nibble
    assert.strictEqual(facadeBytes[6] >> 4, 4);
    assert.strictEqual(facadeBytes[6] & 0x0f, originalBytes[6] & 0x0f);

    // random bits and variant (bytes 7-15) are unchanged
    assert.deepStrictEqual(facadeBytes.slice(7), originalBytes.slice(7));
  });

  test('Uint8Array round-trip, without mutating input', () => {
    const original = parse(v7());
    const originalCopy = Uint8Array.from(original);
    const facade = v7ToV4(original, KEY);

    assert.ok(facade instanceof Uint8Array);
    assert.notStrictEqual(facade, original);
    assert.deepStrictEqual(original, originalCopy);
    assert.deepStrictEqual(v4ToV7(facade, KEY), original);
  });

  test('different keys produce different facades', () => {
    const otherKey = Uint8Array.from(KEY);
    otherKey[0] ^= 0x01;

    const original = v7();
    assert.notStrictEqual(v7ToV4(original, KEY), v7ToV4(original, otherKey));
  });

  test('throws on invalid key', () => {
    // shorter than 16 bytes
    assert.throws(() => v7ToV4(v7(), new Uint8Array(15)), TypeError);
    assert.throws(() => v4ToV7(REF_V4, new Uint8Array(15)), TypeError);
    // 16 bytes of identical values (e.g. all-zero buffer)
    assert.throws(() => v7ToV4(v7(), new Uint8Array(16)), TypeError);
    assert.throws(
      () => v4ToV7(REF_V4, new Uint8Array(16).fill(0xab)),
      TypeError,
    );
  });

  test('accepts keys of 16 or more bytes', () => {
    assert.doesNotThrow(() => v7ToV4(v7(), KEY));
    // longer-than-16 all-zero is allowed: it is SHA-256 derived, not weak
    assert.doesNotThrow(() => v7ToV4(v7(), new Uint8Array(20)));
  });

  test('throws on wrong-length Uint8Array input', () => {
    assert.throws(() => v7ToV4(new Uint8Array(10), KEY), TypeError);
    assert.throws(() => v7ToV4(new Uint8Array(20), KEY), TypeError);
  });

  test('throws on version mismatch', () => {
    assert.throws(() => v7ToV4(REF_V4, KEY), TypeError);
    assert.throws(() => v4ToV7(REF_V7, KEY), TypeError);
  });

  test('throws on invalid UUID string', () => {
    assert.throws(() => v7ToV4('not a uuid', KEY), TypeError);
  });
});
