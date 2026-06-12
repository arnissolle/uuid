import * as assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { describe, test } from 'node:test';
import sha256 from '../sha256.js';

const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex');
const enc = (str: string) => new TextEncoder().encode(str);

describe('sha256', () => {
  // FIPS 180-4 / NIST example vectors
  test('reference vectors', () => {
    assert.strictEqual(
      hex(sha256(enc(''))),
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
    assert.strictEqual(
      hex(sha256(enc('abc'))),
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
    // 56-byte input: exercises the extra padding block at the 64-byte boundary
    assert.strictEqual(
      hex(
        sha256(enc('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')),
      ),
      '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
    );
  });

  test('matches node:crypto across lengths (including block boundaries)', () => {
    for (let len = 0; len <= 200; len++) {
      const input = randomBytes(len);
      assert.strictEqual(
        hex(sha256(new Uint8Array(input))),
        createHash('sha256').update(input).digest('hex'),
      );
    }
  });
});
