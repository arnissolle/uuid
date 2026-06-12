// SipHash-2-4, as specified in https://www.aumasson.jp/siphash/siphash.pdf
//
// Internal module used by v7ToV4() and v4ToV7() for timestamp masking. Not
// part of the public API.

const MASK_64 = 0xffffffffffffffffn;

function rotl(x: bigint, n: bigint) {
  return ((x << n) & MASK_64) | (x >> (64n - n));
}

// Read an unsigned 64-bit little-endian word
function readLE64(bytes: Uint8Array, offset: number) {
  let word = 0n;
  for (let i = 7; i >= 0; i--) {
    word = (word << 8n) | BigInt(bytes[offset + i]);
  }
  return word;
}

/**
 * Compute the SipHash-2-4 MAC of a message.
 *
 * @param {Uint8Array} data - The message bytes
 * @param {Uint8Array} key - The 128-bit key (16 bytes)
 * @returns {bigint} The 64-bit MAC (unsigned)
 */
export default function siphash24(data: Uint8Array, key: Uint8Array): bigint {
  const k0 = readLE64(key, 0);
  const k1 = readLE64(key, 8);

  let v0 = 0x736f6d6570736575n ^ k0;
  let v1 = 0x646f72616e646f6dn ^ k1;
  let v2 = 0x6c7967656e657261n ^ k0;
  let v3 = 0x7465646279746573n ^ k1;

  function sipRound() {
    v0 = (v0 + v1) & MASK_64;
    v1 = rotl(v1, 13n);
    v1 ^= v0;
    v0 = rotl(v0, 32n);
    v2 = (v2 + v3) & MASK_64;
    v3 = rotl(v3, 16n);
    v3 ^= v2;
    v0 = (v0 + v3) & MASK_64;
    v3 = rotl(v3, 21n);
    v3 ^= v0;
    v2 = (v2 + v1) & MASK_64;
    v1 = rotl(v1, 17n);
    v1 ^= v2;
    v2 = rotl(v2, 32n);
  }

  const fullBlocks = data.length - (data.length % 8);

  for (let offset = 0; offset < fullBlocks; offset += 8) {
    const m = readLE64(data, offset);

    v3 ^= m;
    sipRound();
    sipRound();
    v0 ^= m;
  }

  // Final block: remaining bytes (little-endian, zero-padded) with the
  // message length (mod 256) in the most significant byte
  let last = BigInt(data.length & 0xff) << 56n;

  for (let i = fullBlocks; i < data.length; i++) {
    last |= BigInt(data[i]) << BigInt(8 * (i - fullBlocks));
  }

  v3 ^= last;
  sipRound();
  sipRound();
  v0 ^= last;

  v2 ^= 0xffn;
  sipRound();
  sipRound();
  sipRound();
  sipRound();

  return (v0 ^ v1 ^ v2 ^ v3) & MASK_64;
}
