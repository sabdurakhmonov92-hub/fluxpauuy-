/**
 * =============================================================================
 * FLXP1 Canonical Request Signing Scheme — Node.js / TypeScript Port
 * =============================================================================
 * Vendoring Law:
 * This module has ZERO external npm dependencies. It relies exclusively on Node.js
 * built-in `node:crypto`.
 *
 * FLXP1 CANONICAL ENCODING SPECIFICATION (Byte-exact):
 * -----------------------------------------------------
 *     canonical = (
 *         "FLXP1"            || 0x0A ||
 *         METHOD_UPPER       || 0x0A ||
 *         PATH               || 0x0A ||
 *         TIMESTAMP_MS_DEC   || 0x0A ||
 *         NONCE              || 0x0A ||
 *         SHA256_HEX_LOWER(raw_body)
 *     )
 *     signature = lowercase_hex( HMAC-SHA256( agent_secret, canonical ) )
 *
 * HEADERS CONTRACT:
 * -----------------
 *     Authorization: FLXP1 <agent_id>:<signature_hex>
 *     X-FLX-Timestamp: <epoch_ms_ascii_decimal>
 *     X-FLX-Nonce: <client_generated_nonce>
 *     X-FLX-Idempotency-Key: <opaque_client_key> (Required on POST writes)
 *
 * STOP-THE-LINE KAT NOTE:
 * -----------------------
 * FROZEN_VECTORS below are identical copies of Task 19's server vectors.
 * The cross-language contract guarantees byte-for-byte signature equivalence.
 * =============================================================================
 */

import { Buffer } from "node:buffer";
import crypto from "node:crypto";
import type { FrozenVector } from "./types.js";

// Scheme protocol identifier
export const SCHEME = "FLXP1";

// Structural canonical line separator (ASCII 0x0A / newline)
export const SEPARATOR = "\n";

// Header name constants
export const HEADER_AUTH = "Authorization";
export const HEADER_TIMESTAMP = "X-FLX-Timestamp";
export const HEADER_NONCE = "X-FLX-Nonce";
export const HEADER_IDEMPOTENCY = "X-FLX-Idempotency-Key";

// Strict validation regexes matching server-side canonical.py
const METHOD_REGEX = /^[A-Za-z]+$/;
const PATH_REGEX = /^\/[A-Za-z0-9._~/-]*$/;
const TIMESTAMP_REGEX = /^[0-9]{13}$/;
const NONCE_REGEX = /^[A-Za-z0-9]{16,64}$/;
const IDEMPOTENCY_KEY_REGEX = /^[A-Za-z0-9-]{16,128}$/;
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SIG_REGEX = /^[0-9a-f]{64}$/;

/**
 * Frozen Known Answer Test (KAT) vectors identical to Task 19 canonical.py.
 */
export const FROZEN_VECTORS: readonly FrozenVector[] = Object.freeze([
  // Vector 1: Empty body POST (proves empty payload hashing)
  {
    secret: "test-secret-key-32-bytes-long!!",
    method: "POST",
    path: "/v1/payments/empty",
    timestamp: "1774472400000",
    nonce: "abcdef0123456789",
    body: "",
    expected_canonical:
      "FLXP1\nPOST\n/v1/payments/empty\n1774472400000\nabcdef0123456789\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    expected_signature:
      "4f33eb63343aa8d19ac3adb785c5ee7d30e2a14bdee3bb48d23e19e90bde12c7",
  },
  // Vector 2: Typical JSON payment body (proves multi-field payload hashing)
  {
    secret: "test-secret-key-32-bytes-long!!",
    method: "POST",
    path: "/v1/payments",
    timestamp: "1774472400000",
    nonce: "fedcba9876543210",
    body: '{"amount":10000,"currency":"USDC","recipient_id":"018f2d5a-8b1e-7b2c-9d3e-4f5a6b7c8d9e"}',
    expected_canonical:
      "FLXP1\nPOST\n/v1/payments\n1774472400000\nfedcba9876543210\nbb847548619233d487cce199b61cd1235c85925e63e5dec6108be1176fd87b52",
    expected_signature:
      "3dc25e0205bba581b3acdadb09503d183bdda58a9f712594d1d3ad9f0cc5ad5d",
  },
  // Vector 3: GET request without body (proves zero-length body on read endpoint)
  {
    secret: "test-secret-key-32-bytes-long!!",
    method: "GET",
    path: "/v1/agents/me",
    timestamp: "1774472400000",
    nonce: "1234567890abcdef",
    body: "",
    expected_canonical:
      "FLXP1\nGET\n/v1/agents/me\n1774472400000\n1234567890abcdef\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    expected_signature:
      "1564b8f509dd03b1ac17f99a9bdf6ac98c0cf564f0d305ac814c290167833f66",
  },
]);

export function get_frozen_vectors(): readonly FrozenVector[] {
  return FROZEN_VECTORS;
}

/**
 * Compute lowercase hex SHA-256 digest of raw request body.
 */
export function sha256_hex(body: Uint8Array | Buffer | string = ""): string {
  const hash = crypto.createHash("sha256");
  if (typeof body === "string") {
    hash.update(body, "utf8");
  } else {
    hash.update(body);
  }
  return hash.digest("hex").toLowerCase();
}

/**
 * Validate timestamp format (13-digit epoch milliseconds string).
 */
export function validate_timestamp(ts: string): void {
  if (typeof ts !== "string") {
    throw new TypeError("timestamp: must be a string");
  }
  if (!TIMESTAMP_REGEX.test(ts)) {
    throw new RangeError(
      "timestamp: must be exactly 13-digit epoch milliseconds decimal"
    );
  }
}

/**
 * Validate client nonce format (16-64 alphanumeric characters).
 */
export function validate_nonce(nonce: string): void {
  if (typeof nonce !== "string") {
    throw new TypeError("nonce: must be a string");
  }
  if (!NONCE_REGEX.test(nonce)) {
    throw new RangeError(
      "nonce: must be 16-64 alphanumeric characters [A-Za-z0-9]"
    );
  }
}

/**
 * Validate idempotency key shape (16-128 alphanumeric characters and hyphens).
 */
export function validate_idempotency_key(key: string): void {
  if (typeof key !== "string") {
    throw new TypeError("idempotency_key: must be a string");
  }
  if (!IDEMPOTENCY_KEY_REGEX.test(key)) {
    throw new RangeError(
      "idempotency_key: must be 16-128 characters matching [A-Za-z0-9-]"
    );
  }
}

/**
 * Construct byte-exact canonical payload buffer.
 */
export function canonical_bytes(
  method: string,
  path: string,
  timestamp: string,
  nonce: string,
  body: Uint8Array | Buffer | string = ""
): Buffer {
  if (typeof method !== "string" || !METHOD_REGEX.test(method)) {
    throw new TypeError("method: must be valid alphabetic HTTP method token");
  }
  const methodUpper = method.toUpperCase();

  if (typeof path !== "string") {
    throw new TypeError("path: must be a string");
  }
  if (path.includes("\n")) {
    throw new RangeError("path: must not contain newline");
  }
  if (path.includes("?")) {
    throw new RangeError(
      "path: query strings forbidden; signed path must not contain '?'"
    );
  }
  if (!path.startsWith("/")) {
    throw new RangeError(`path: must start with '/', got '${path}'`);
  }
  if (!PATH_REGEX.test(path)) {
    throw new RangeError(`path: invalid characters in path, got '${path}'`);
  }

  validate_timestamp(timestamp);
  validate_nonce(nonce);

  const bodyDigest = sha256_hex(body);

  const canonicalString = [
    SCHEME,
    methodUpper,
    path,
    timestamp,
    nonce,
    bodyDigest,
  ].join(SEPARATOR);

  return Buffer.from(canonicalString, "ascii");
}

/**
 * Compute HMAC-SHA256 signature for canonical request payload.
 *
 * @param secret Secret key material (Buffer, Uint8Array, or string).
 * @param method HTTP method (e.g. 'POST', 'GET').
 * @param path Absolute request path starting with '/'.
 * @param timestamp 13-digit epoch milliseconds string.
 * @param nonce 16-64 alphanumeric client nonce.
 * @param body Raw request body.
 * @returns 64-character lowercase hex HMAC-SHA256 signature.
 */
export function sign(
  secret: Uint8Array | Buffer | string,
  method: string,
  path: string,
  timestamp: string,
  nonce: string,
  body: Uint8Array | Buffer | string = ""
): string {
  const secretBuffer =
    typeof secret === "string" ? Buffer.from(secret, "utf8") : Buffer.from(secret);

  const rawCanonical = canonical_bytes(method, path, timestamp, nonce, body);
  return crypto
    .createHmac("sha256", secretBuffer)
    .update(rawCanonical)
    .digest("hex")
    .toLowerCase();
}

/**
 * Verify incoming signature against computed HMAC-SHA256.
 *
 * Adversarial Totality Rule:
 * Returns false immediately without throwing on malformed inputs.
 * Uses `crypto.timingSafeEqual` to eliminate timing side channels.
 */
export function verify(
  secret: Uint8Array | Buffer | string,
  providedSig: string,
  method: string,
  path: string,
  timestamp: string,
  nonce: string,
  body: Uint8Array | Buffer | string = ""
): boolean {
  if (typeof providedSig !== "string" || !SIG_REGEX.test(providedSig)) {
    return false;
  }

  try {
    const expectedSig = sign(secret, method, path, timestamp, nonce, body);
    const expectedBuf = Buffer.from(expectedSig, "ascii");
    const providedBuf = Buffer.from(providedSig, "ascii");

    if (expectedBuf.length !== providedBuf.length) {
      return false;
    }
    return crypto.timingSafeEqual(expectedBuf, providedBuf);
  } catch {
    return false;
  }
}

/**
 * Parse and validate HTTP Authorization header.
 * Expected format: "FLXP1 <agent_id>:<signature_hex>"
 */
export function parse_authorization(header: string | null | undefined): [string, string] {
  if (!header || typeof header !== "string") {
    throw new TypeError("authorization header: missing or empty");
  }

  const spaceIndex = header.indexOf(" ");
  if (spaceIndex === -1) {
    throw new RangeError("authorization header scheme: missing separator or credentials");
  }

  const scheme = header.substring(0, spaceIndex);
  if (scheme !== SCHEME) {
    throw new RangeError(`authorization header scheme: must be '${SCHEME}'`);
  }

  const credentials = header.substring(spaceIndex + 1);
  if (credentials.startsWith(" ")) {
    throw new RangeError("authorization header: unexpected whitespace after scheme");
  }

  const colonIndex = credentials.indexOf(":");
  if (colonIndex === -1) {
    throw new RangeError("authorization header credentials: missing colon separator");
  }

  const agentId = credentials.substring(0, colonIndex);
  const sig = credentials.substring(colonIndex + 1);

  if (!UUID_REGEX.test(agentId)) {
    throw new RangeError(
      "authorization header agent_id: must be canonical lowercase hyphenated UUID"
    );
  }

  if (!SIG_REGEX.test(sig)) {
    throw new RangeError(
      "authorization header signature: must be 64-character lowercase hex"
    );
  }

  return [agentId, sig];
}
