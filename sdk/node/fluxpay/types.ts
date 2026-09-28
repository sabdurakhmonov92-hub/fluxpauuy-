/**
 * Wire shapes and types for FluxPay Node SDK.
 *
 * Vendoring Law:
 * Mirrored interfaces corresponding to Task 24 schemas with zero server dependencies.
 */

export type PaymentStatus = "settled" | "held";

export interface PaymentResult {
  /** Unique payment identifier (UUID corresponding 1:1 with ledger tx_id). */
  id: string;
  /** Terminal execution status ('settled' | 'held'). */
  status: PaymentStatus;
}

export interface Balance {
  /** Available ledger balance in integer minor units (non-negative). */
  balance: number;
  /** Currency code (e.g. 'USDC'). */
  currency: string;
}

export interface PaymentDetail {
  /** Unique payment identifier (UUID). */
  id: string;
  /** Payment execution status ('settled' | 'held'). */
  status: PaymentStatus;
  /** Payment amount in integer minor units. */
  amount: number;
  /** Currency code. */
  currency: string;
  /** Creation timestamp (UTC ISO-8601 string). */
  created_at: string;
}

export interface ErrorBody {
  /** Machine-readable error code. */
  code: string;
  /** Sanitized error description. */
  message: string;
  /** Indicates whether client agents may safely retry. */
  retryable: boolean;
}

export interface ErrorEnvelope {
  error: ErrorBody;
}

export interface FrozenVector {
  secret: string;
  method: string;
  path: string;
  timestamp: string;
  nonce: string;
  body: string;
  expected_canonical: string;
  expected_signature: string;
}

export interface FluxPayClientOptions {
  /** Calling agent's UUID identifier. */
  agentId: string;
  /** Calling agent's secret key (from one-time creation display). */
  secret: string;
  /** Base URL of the FluxPay gateway (e.g. 'https://api.fluxpay.dev'). */
  baseUrl: string;
  /** Request timeout in milliseconds (default: 10000). */
  timeoutMs?: number;
  /** Maximum retry attempts on transient errors (default: 3). */
  maxRetries?: number;
  /** Optional custom fetch implementation (for testing or proxying). */
  fetchFn?: typeof fetch;
  /** Optional custom sleep function for testability (defaults to setTimeout). */
  sleepFn?: (ms: number) => Promise<void>;
}

export interface PayOptions {
  /** Target merchant external handle (e.g. 'merchant_demo'). */
  to: string;
  /** Payment amount in integer minor units (e.g. 1050 = $10.50 USDC). */
  amount: number;
  /** Currency code (default: 'USDC'). */
  currency?: string;
  /** Optional idempotency key (16-128 alphanumeric chars and hyphens). */
  idempotencyKey?: string;
}
