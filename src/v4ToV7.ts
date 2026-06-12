import type { NonSharedArrayBuffer, UUIDTypes } from './types.js';
import v47 from './v47.js';

/**
 * Convert a v4 UUID created by `v7ToV4()` back to the original v7 UUID by
 * unmasking the timestamp with SipHash-2-4
 *
 * The conversion is unauthenticated: any well-formed v4 UUID will decode to
 * some v7 UUID. Decoded values must not be trusted as authentic; validate
 * them against application state (existence, authorization) before use.
 *
 * @param {string|Uint8Array} uuid - The v4 UUID to convert back to v7
 * @param {Uint8Array} key - The 16-byte secret key used by `v7ToV4()`
 * @returns {string|Uint8Array} The v7 UUID as the same type as the `uuid` arg
 * (string or Uint8Array)
 */
export default function v4ToV7(uuid: string, key: Uint8Array): string;
export default function v4ToV7(
  uuid: Uint8Array,
  key: Uint8Array,
): NonSharedArrayBuffer;
export default function v4ToV7(
  uuid: UUIDTypes,
  key: Uint8Array,
): UUIDTypes<NonSharedArrayBuffer> {
  return v47(uuid, key, 0x40, 0x70);
}
