import type { NonSharedArrayBuffer, UUIDTypes } from './types.js';
import v47 from './v47.js';

/**
 * Convert a v7 UUID to a v4 UUID by masking the timestamp with SipHash-2-4
 *
 * This allows storing time-ordered v7 UUIDs in databases (better index
 * locality) while emitting RFC-valid v4 UUIDs externally, without revealing
 * the embedded timestamp. The conversion is exactly reversible with
 * `v4ToV7()` and the same key, and is interoperable with the uuid47 reference
 * implementation and Symfony's `Uuid47Transformer`.
 *
 * Note: This is timestamp obfuscation, not authenticated encryption. The
 * mapping is deterministic (required for reversibility), and any well-formed
 * v4 UUID will decode to some v7 UUID, so decoded values must be validated
 * against application state before use.
 *
 * @param {string|Uint8Array} uuid - The v7 UUID to convert to v4
 * @param {Uint8Array} key - 16-byte secret key (use cryptographically random
 * bytes, and keep it stable for the lifetime of the stored UUIDs)
 * @returns {string|Uint8Array} The v4 UUID as the same type as the `uuid` arg
 * (string or Uint8Array)
 */
export default function v7ToV4(uuid: string, key: Uint8Array): string;
export default function v7ToV4(
  uuid: Uint8Array,
  key: Uint8Array,
): NonSharedArrayBuffer;
export default function v7ToV4(
  uuid: UUIDTypes,
  key: Uint8Array,
): UUIDTypes<NonSharedArrayBuffer> {
  return v47(uuid, key, 0x70, 0x40);
}
