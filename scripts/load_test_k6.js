import http from 'k6/http';
import { check, sleep } from 'k6';

// ==============================================================================
// FluxPay Production Load Testing Script (k6) - Part 8.2 & 10.3
// Target: 1,000 RPS for 10 minutes
// SLA Thresholds:
// - http_req_duration (p99) < 500ms
// - http_req_failed < 0.1% (99.9% success rate)
// ==============================================================================

export const options = {
  scenarios: {
    constant_request_rate: {
      executor: 'constant-arrival-rate',
      rate: 1000,
      timeUnit: '1s',
      duration: '10m',
      preAllocatedVUs: 200,
      maxVUs: 1000,
    },
  },
  thresholds: {
    http_req_duration: ['p(95)<250', 'p(99)<500'],
    http_req_failed: ['rate<0.001'], // < 0.1% error rate
  },
};

const BASE_URL = __ENV.FLX_TARGET_URL || 'http://localhost:8000';

export default function () {
  const agentId = '00000000-0000-0000-0000-000000000001';
  const timestamp = Date.now();
  const idemKey = `load_${__VU}_${__ITER}_${timestamp}`;

  // 1. Health Probe
  const healthRes = http.get(`${BASE_URL}/health`);
  check(healthRes, {
    'health returns 200': (r) => r.status === 200,
  });

  // 2. x402 Payment Challenge Generation
  const challengePayload = JSON.stringify({
    resource_id: 'agent_compute_session',
    amount: 50000, // 0.05 USDC
    payee: '0x1111111111111111111111111111111111111111',
  });

  const challengeRes = http.post(`${BASE_URL}/x402/challenge`, challengePayload, {
    headers: { 'Content-Type': 'application/json' },
  });

  check(challengeRes, {
    'x402 challenge status 200': (r) => r.status === 200,
    'x402 challenge returns nonce': (r) => JSON.parse(r.body).challenge.nonce !== undefined,
  });

  // 3. Balance Query
  const balanceRes = http.get(`${BASE_URL}/v1/balance`, {
    headers: {
      'X-Agent-ID': agentId,
      'X-Timestamp': String(timestamp),
    },
  });

  check(balanceRes, {
    'balance status 200 or 401 (auth enforced)': (r) => r.status === 200 || r.status === 401,
  });

  sleep(0.05);
}
