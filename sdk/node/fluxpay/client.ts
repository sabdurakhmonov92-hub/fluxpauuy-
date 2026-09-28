/**
 * =============================================================================
 * FluxPay Node.js / TypeScript SDK Client
 * =============================================================================
 * Zero-Dependency Law:
 * Relies strictly on Node 18+ built-ins: `node:crypto` and global `fetch`.
 * No external runtime npm packages required.
 *
 * Retry Law (Task 4 Parity):
 * - Bounded exponential backoff with jitter on 429, 502, 503, and network timeouts.
 * - Non-retryable failures (400, 401, 403, 404, 409, 422) fail immediately.
 * - Idempotency keys are preserved across retries of write operations.
 * =============================================================================
 */

import crypto from "node:crypto";
import {
  HEADER_AUTH,
  HEADER_IDEMPOTENCY,
  HEADER_NONCE,
  HEADER_TIMESTAMP,
  sign,
  validate_idempotency_key,
} from "./signing.js";
import type {
  Balance,
  ErrorEnvelope,
  FluxPayClientOptions,
  PaymentDetail,
  PaymentResult,
  PayOptions,
} from "./types.js";

export const MERCHANT_ID_PATTERN = "^[a-z0-9_.-]{3,64}$";
const MERCHANT_REGEX = new RegExp(MERCHANT_ID_PATTERN);

export const CURRENCY_PATTERN = "^[A-Z0-9]{2,10}$";
const CURRENCY_REGEX = new RegExp(CURRENCY_PATTERN);

// =============================================================================
// Typed Error Classes
// =============================================================================

export class FluxPayError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FluxPayError";
  }
}

export class FluxPayApiError extends FluxPayError {
  readonly code: string;
  readonly retryable: boolean;
  readonly status: number;

  constructor({
    code,
    message,
    retryable,
    status,
  }: {
    code: string;
    message: string;
    retryable: boolean;
    status: number;
  }) {
    super(`[${status}] ${code}: ${message} (retryable=${retryable})`);
    this.name = "FluxPayApiError";
    this.code = code;
    this.retryable = retryable;
    this.status = status;
  }
}

export class FluxPayNetworkError extends FluxPayError {
  readonly retryable: boolean;
  readonly cause?: unknown;

  constructor(message: string, { retryable = true, cause }: { retryable?: boolean; cause?: unknown } = {}) {
    super(message);
    this.name = "FluxPayNetworkError";
    this.retryable = retryable;
    this.cause = cause;
  }
}

// =============================================================================
// Client Implementation
// =============================================================================

export class FluxPayClient {
  private readonly agentId: string;
  private readonly secret: string;
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly fetchImpl: typeof fetch;
  private readonly sleepImpl: (ms: number) => Promise<void>;

  constructor(options: FluxPayClientOptions) {
    this.agentId = options.agentId.trim();
    this.secret = options.secret;
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.timeoutMs = options.timeoutMs ?? 10000;
    this.maxRetries = options.maxRetries ?? 3;
    this.fetchImpl = options.fetchFn ?? globalThis.fetch;
    this.sleepImpl =
      options.sleepFn ?? ((ms: number) => new Promise((resolve) => setTimeout(resolve, ms)));
  }

  /**
   * Execute a payment transfer to a merchant (The 3-Line Face).
   */
  async pay(options: PayOptions): Promise<PaymentResult> {
    const { to, amount, currency = "USDC", idempotencyKey } = options;

    if (!MERCHANT_REGEX.test(to)) {
      throw new RangeError(
        `Invalid merchant id format: '${to}'. Must match ${MERCHANT_ID_PATTERN}`
      );
    }
    if (!Number.isInteger(amount) || amount <= 0) {
      throw new RangeError(`Amount must be a positive integer in minor units, got ${amount}`);
    }
    if (!CURRENCY_REGEX.test(currency)) {
      throw new RangeError(`Invalid currency format: '${currency}'. Must match ${CURRENCY_PATTERN}`);
    }

    const idem = idempotencyKey ?? crypto.randomUUID().replace(/-/g, "");
    validate_idempotency_key(idem);

    const payload = JSON.stringify({ to, amount, currency });

    const response = await this.requestWithRetry({
      method: "POST",
      path: "/v1/payments",
      body: payload,
      idem,
    });

    const data = (await response.json()) as { id?: string; status?: "settled" | "held" };
    if (!data.id || (data.status !== "settled" && data.status !== "held")) {
      throw new FluxPayApiError({
        code: "invalid_response",
        message: `Malformed payment response: ${JSON.stringify(data)}`,
        retryable: false,
        status: response.status,
      });
    }

    return {
      id: data.id,
      status: data.status,
    };
  }

  /**
   * Retrieve payment details by ID.
   */
  async getPayment(paymentId: string): Promise<PaymentDetail> {
    const pid = paymentId.trim();
    const response = await this.requestWithRetry({
      method: "GET",
      path: `/v1/payments/${pid}`,
      body: "",
    });

    const data = (await response.json()) as PaymentDetail;
    if (!data.id || (data.status !== "settled" && data.status !== "held")) {
      throw new FluxPayApiError({
        code: "invalid_response",
        message: `Malformed payment detail response: ${JSON.stringify(data)}`,
        retryable: false,
        status: response.status,
      });
    }

    return data;
  }

  /**
   * Retrieve the available balance for the authenticated agent.
   */
  async balance(currency = "USDC"): Promise<Balance> {
    void currency; // In FLXP1, query parameters are forbidden; GET /v1/balance evaluates account
    const response = await this.requestWithRetry({
      method: "GET",
      path: "/v1/balance",
      body: "",
    });

    const data = (await response.json()) as Balance;
    if (typeof data.balance !== "number" || typeof data.currency !== "string") {
      throw new FluxPayApiError({
        code: "invalid_response",
        message: `Malformed balance response: ${JSON.stringify(data)}`,
        retryable: false,
        status: response.status,
      });
    }

    return data;
  }

  /**
   * Request execution with bounded retries and idempotency preservation.
   */
  private async requestWithRetry({
    method,
    path,
    body,
    idem,
  }: {
    method: string;
    path: string;
    body: string;
    idem?: string;
  }): Promise<Response> {
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      const timestamp = Date.now().toString();
      const nonce = crypto.randomUUID().replace(/-/g, "");

      const signature = sign(
        this.secret,
        method,
        path,
        timestamp,
        nonce,
        body
      );

      const headers: Record<string, string> = {
        [HEADER_AUTH]: `FLXP1 ${this.agentId}:${signature}`,
        [HEADER_TIMESTAMP]: timestamp,
        [HEADER_NONCE]: nonce,
      };

      if (idem) {
        headers[HEADER_IDEMPOTENCY] = idem;
      }
      if (body.length > 0) {
        headers["Content-Type"] = "application/json";
      }

      let response: Response;
      try {
        const signal = AbortSignal.timeout(this.timeoutMs);
        response = await this.fetchImpl(`${this.baseUrl}${path}`, {
          method,
          headers,
          body: body.length > 0 ? body : undefined,
          signal,
        });
      } catch (err: unknown) {
        if (attempt < this.maxRetries) {
          const backoff = Math.min(8000, 500 * Math.pow(2, attempt) + Math.random() * 100);
          await this.sleepImpl(backoff);
          continue;
        }
        throw new FluxPayNetworkError(
          `Network request failed after ${this.maxRetries} retries: ${String(err)}`,
          { retryable: true, cause: err }
        );
      }

      if (response.ok) {
        return response;
      }

      // Retryable HTTP status codes per Task 4: 429, 502, 503
      if (response.status === 429 || response.status === 502 || response.status === 503) {
        if (attempt < this.maxRetries) {
          const backoff = Math.min(8000, 500 * Math.pow(2, attempt) + Math.random() * 100);
          await this.sleepImpl(backoff);
          continue;
        }
        throw await this.parseErrorEnvelope(response);
      }

      // Non-retryable error
      throw await this.parseErrorEnvelope(response);
    }

    throw new FluxPayNetworkError(`Request failed after ${this.maxRetries} retries`, {
      retryable: true,
    });
  }

  private async parseErrorEnvelope(response: Response): Promise<FluxPayApiError> {
    try {
      const text = await response.text();
      const parsed = JSON.parse(text) as ErrorEnvelope;
      if (parsed?.error && typeof parsed.error === "object") {
        return new FluxPayApiError({
          code: parsed.error.code || "unknown_error",
          message: parsed.error.message || text,
          retryable: Boolean(parsed.error.retryable),
          status: response.status,
        });
      }
      return new FluxPayApiError({
        code: "http_error",
        message: text || `HTTP ${response.status}`,
        retryable: response.status === 429 || response.status === 502 || response.status === 503,
        status: response.status,
      });
    } catch {
      return new FluxPayApiError({
        code: "http_error",
        message: `HTTP ${response.status}`,
        retryable: response.status === 429 || response.status === 502 || response.status === 503,
        status: response.status,
      });
    }
  }
}
