import assert from "node:assert/strict";
import test, { describe, it } from "node:test";
import { FluxPayApiError, FluxPayClient, FluxPayNetworkError } from "../dist/client.js";

describe("FluxPayClient (Node Port)", () => {
  const agentId = "018f2d5a-8b1e-7b2c-9d3e-4f5a6b7c8d9e";
  const secret = "test-secret-key-32-bytes-long!!";
  const baseUrl = "https://api.test";

  it("retries 429 rate limit errors and preserves idempotency key across attempts", async () => {
    let callCount = 0;
    const capturedHeaders = [];

    const mockFetch = async (url, init) => {
      callCount++;
      capturedHeaders.push({ ...init.headers });
      if (callCount < 3) {
        return new Response(
          JSON.stringify({
            error: {
              code: "rate_limited",
              message: "Too many requests. Please retry after backoff.",
              retryable: true,
            },
          }),
          { status: 429, headers: { "Content-Type": "application/json" } }
        );
      }
      return new Response(
        JSON.stringify({
          id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
          status: "settled",
        }),
        { status: 201, headers: { "Content-Type": "application/json" } }
      );
    };

    const client = new FluxPayClient({
      agentId,
      secret,
      baseUrl,
      fetchFn: mockFetch,
      sleepFn: async () => {}, // Zero-delay sleep for instant tests
      maxRetries: 3,
    });

    const result = await client.pay({
      to: "merchant_demo",
      amount: 1050,
      currency: "USDC",
      idempotencyKey: "test-idem-key-123456789",
    });

    assert.equal(callCount, 3);
    assert.equal(result.status, "settled");
    assert.equal(result.id, "a1b2c3d4-e5f6-7890-abcd-ef1234567890");

    // The SAME idempotency key was sent on all attempts
    for (const h of capturedHeaders) {
      assert.equal(h["X-FLX-Idempotency-Key"], "test-idem-key-123456789");
    }

    // But timestamps and nonces were fresh across attempts
    assert.notEqual(capturedHeaders[0]["X-FLX-Nonce"], capturedHeaders[1]["X-FLX-Nonce"]);
  });

  it("never retries non-retryable 400 InsufficientFunds", async () => {
    let callCount = 0;
    const mockFetch = async () => {
      callCount++;
      return new Response(
        JSON.stringify({
          error: {
            code: "insufficient_funds",
            message: "Account does not have sufficient available balance.",
            retryable: false,
          },
        }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    };

    const client = new FluxPayClient({
      agentId,
      secret,
      baseUrl,
      fetchFn: mockFetch,
      sleepFn: async () => {},
      maxRetries: 3,
    });

    await assert.rejects(
      async () => {
        await client.pay({
          to: "merchant_demo",
          amount: 500000,
        });
      },
      (err) => {
        assert(err instanceof FluxPayApiError);
        assert.equal(err.code, "insufficient_funds");
        assert.equal(err.retryable, false);
        assert.equal(err.status, 400);
        return true;
      }
    );

    assert.equal(callCount, 1, "Non-retryable 400 must fail immediately without retrying");
  });

  it("never retries non-retryable 404 NotFound", async () => {
    let callCount = 0;
    const mockFetch = async () => {
      callCount++;
      return new Response(
        JSON.stringify({
          error: {
            code: "not_found",
            message: "The requested resource was not found.",
            retryable: false,
          },
        }),
        { status: 404, headers: { "Content-Type": "application/json" } }
      );
    };

    const client = new FluxPayClient({
      agentId,
      secret,
      baseUrl,
      fetchFn: mockFetch,
      sleepFn: async () => {},
      maxRetries: 3,
    });

    await assert.rejects(
      async () => {
        await client.getPayment("a1b2c3d4-e5f6-7890-abcd-ef1234567890");
      },
      (err) => {
        assert(err instanceof FluxPayApiError);
        assert.equal(err.code, "not_found");
        assert.equal(err.retryable, false);
        assert.equal(err.status, 404);
        return true;
      }
    );

    assert.equal(callCount, 1, "404 must fail immediately");
  });

  it("raises FluxPayNetworkError when retries are exhausted on network failures", async () => {
    let callCount = 0;
    const mockFetch = async () => {
      callCount++;
      throw new Error("Connection reset by peer");
    };

    const client = new FluxPayClient({
      agentId,
      secret,
      baseUrl,
      fetchFn: mockFetch,
      sleepFn: async () => {},
      maxRetries: 2,
    });

    await assert.rejects(
      async () => {
        await client.balance();
      },
      (err) => {
        assert(err instanceof FluxPayNetworkError);
        assert.equal(err.retryable, true);
        return true;
      }
    );

    assert.equal(callCount, 3, "Initial attempt + 2 retries = 3 attempts total");
  });

  it("validates merchant handle and amount client-side before sending network request", async () => {
    let callCount = 0;
    const mockFetch = async () => {
      callCount++;
      return new Response("{}", { status: 200 });
    };

    const client = new FluxPayClient({
      agentId,
      secret,
      baseUrl,
      fetchFn: mockFetch,
    });

    await assert.rejects(async () => {
      await client.pay({ to: "INVALID MERCHANT!", amount: 100 });
    }, RangeError);

    await assert.rejects(async () => {
      await client.pay({ to: "merchant_ok", amount: -50 });
    }, RangeError);

    assert.equal(callCount, 0, "No network request must be made on client validation error");
  });
});
