import parse from './parse.js';
import sha256 from './sha256.js';
import siphash24 from './siphash.js';
import { unsafeStringify } from './stringify.js';
import type { NonSharedArrayBuffer, UUIDTypes } from './types.js';

// Convert between v7 and v4 UUIDs by XOR-masking the 48-bit timestamp field
// with a keyed SipHash-2-4 digest of the UUID's own 74 random bits. The
// random bits (with version and variant masked out) are identical in both
// representations, so the same digest is produced in both directions, making
// the mapping exactly reversible under the same key.
//
// This is the same construction as the uuid47 reference implementation and
// Symfony's Uuid47Transformer, so values are interoperable across these
// libraries.
//
// https://github.com/n2p5/uuid47
// https://github.com/symfony/uid/blob/8.1/Uuid47Transformer.php
export default function v47(
  uuid: UUIDTypes,
  key: Uint8Array,
  fromVersion: 0x40 | 0x70,
  toVersion: 0x40 | 0x70,
): UUIDTypes<NonSharedArrayBuffer> {
  // Derive the 16-byte SipHash key, matching Symfony's Uuid47Transformer: a
  // 16-byte secret is used as-is, a longer secret is hashed with SHA-256 and
  // truncated to 16 bytes.
  if (key.length < 16) {
    throw TypeError('Key must be at least 16 bytes');
  }

  // Reject a 16-byte key of all-identical bytes (e.g. an all-zero buffer), as
  // Symfony does. This guards against obvious mistakes; it is not a substitute
  // for a cryptographically random key.
  if (key.length === 16 && key.every((b) => b === key[0])) {
    throw TypeError(
      'Key is trivially weak; use cryptographically random bytes',
    );
  }

  const sipKey = key.length === 16 ? key : sha256(key).subarray(0, 16);

  let bytes: Uint8Array;
  if (typeof uuid === 'string') {
    bytes = parse(uuid);
  } else {
    if (uuid.length !== 16) {
      throw TypeError('UUID must be 16 bytes');
    }
    bytes = Uint8Array.from(uuid);
  }

  if ((bytes[6] & 0xf0) !== fromVersion) {
    throw TypeError(`UUID is not a version ${fromVersion >> 4} UUID`);
  }

  // 10-byte SipHash input = the 74 random bits, with version and variant
  // bits masked out
  const hash = siphash24(
    Uint8Array.of(
      bytes[6] & 0x0f,
      bytes[7],
      bytes[8] & 0x3f,
      bytes[9],
      bytes[10],
      bytes[11],
      bytes[12],
      bytes[13],
      bytes[14],
      bytes[15],
    ),
    sipKey,
  );

  // XOR the timestamp field (bytes 0-5, big-endian) with the low 48 bits of
  // the digest (reversed, since SipHash output is little-endian)
  for (let i = 0; i < 6; i++) {
    bytes[i] ^= Number((hash >> BigInt(8 * (5 - i))) & 0xffn);
  }

  bytes[6] = (bytes[6] & 0x0f) | toVersion;

  return typeof uuid === 'string' ? unsafeStringify(bytes) : bytes;
}
