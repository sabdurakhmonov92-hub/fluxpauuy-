import assert from "node:assert/strict";
import test, { describe, it } from "node:test";
import {
  canonical_bytes,
  FROZEN_VECTORS,
  parse_authorization,
  sha256_hex,
  sign,
  verify,
} from "../dist/signing.js";

describe("FLXP1 Canonical Signing (Node Port)", () => {
  it("satisfies all 3 frozen KAT vectors byte-for-byte", () => {
    for (const v of FROZEN_VECTORS) {
      const computedCanonical = canonical_bytes(
        v.method,
        v.path,
        v.timestamp,
        v.nonce,
        v.body
      );
      assert.equal(
        computedCanonical.toString("ascii"),
        v.expected_canonical
      );

      const computedSig = sign(
        v.secret,
        v.method,
        v.path,
        v.timestamp,
        v.nonce,
        v.body
      );
      assert.equal(computedSig, v.expected_signature);

      assert.equal(
        verify(
          v.secret,
          computedSig,
          v.method,
          v.path,
          v.timestamp,
          v.nonce,
          v.body
        ),
        true
      );
    }
  });

  it("tampering canonical fields alters signature", () => {
    const v = FROZEN_VECTORS[1];
    const baseSig = sign(v.secret, v.method, v.path, v.timestamp, v.nonce, v.body);

    // Method sensitivity
    assert.notEqual(
      sign(v.secret, "GET", v.path, v.timestamp, v.nonce, v.body),
      baseSig
    );

    // Path sensitivity
    assert.notEqual(
      sign(v.secret, v.method, "/v1/payments/other", v.timestamp, v.nonce, v.body),
      baseSig
    );

    // Timestamp sensitivity
    assert.notEqual(
      sign(v.secret, v.method, v.path, "1774472400001", v.nonce, v.body),
      baseSig
    );

    // Nonce sensitivity
    assert.notEqual(
      sign(v.secret, v.method, v.path, v.timestamp, "0123456789fedcba", v.body),
      baseSig
    );

    // Body sensitivity
    assert.notEqual(
      sign(v.secret, v.method, v.path, v.timestamp, v.nonce, v.body + "tampered"),
      baseSig
    );
  });

  it("adversarial verify totality returns false on corrupted inputs", () => {
    const v = FROZEN_VECTORS[0];
    assert.equal(
      verify(v.secret, "not-a-valid-hex-signature", v.method, v.path, v.timestamp, v.nonce, v.body),
      false
    );
    assert.equal(
      verify(v.secret, "0".repeat(64), v.method, v.path, v.timestamp, v.nonce, v.body),
      false
    );
    assert.equal(
      verify(v.secret, "", v.method, v.path, v.timestamp, v.nonce, v.body),
      false
    );
  });

  it("parse_authorization correctly parses valid and rejects malformed headers", () => {
    const [agentId, sig] = parse_authorization(
      "FLXP1 a1b2c3d4-e5f6-7890-abcd-ef1234567890:" + "a".repeat(64)
    );
    assert.equal(agentId, "a1b2c3d4-e5f6-7890-abcd-ef1234567890");
    assert.equal(sig, "a".repeat(64));

    assert.throws(() => parse_authorization(null), TypeError);
    assert.throws(() => parse_authorization(""), TypeError);
    assert.throws(() => parse_authorization("BEARER token"), RangeError);
    assert.throws(() => parse_authorization("FLXP1  two-spaces:sig"), RangeError);
    assert.throws(() => parse_authorization("FLXP1 bad-id:sig"), RangeError);
  });
});
