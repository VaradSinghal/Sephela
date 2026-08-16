// Steady-state read load against the job/status endpoints.
//
// This is the shape of real traffic: a SOC dashboard polls job status and reads
// findings far more often than anyone uploads. It is the scenario that should hold
// its latency SLO under sustained load, because it is what an analyst experiences as
// "is the platform responsive".
//
//   make load-read SEPHELA_URL=https://api.staging.sephela.example
//
// Thresholds are the SLOs from infra/load/README.md. A breach fails the run, which
// is what makes this usable as a release gate rather than a report nobody reads.

import http from 'k6/http';
import { group, sleep } from 'k6';
import { API, authHeaders, classify, login, rateLimited } from './lib/session.js';

export const options = {
  scenarios: {
    // Ramping arrival rate rather than fixed VUs: it holds *request rate* steady
    // regardless of latency. With fixed VUs a slowdown reduces offered load, which
    // hides the very degradation the test exists to find.
    steady_read: {
      executor: 'ramping-arrival-rate',
      startRate: 10,
      timeUnit: '1s',
      preAllocatedVUs: 20,
      maxVUs: 200,
      stages: [
        { target: 50, duration: '2m' },   // ramp
        { target: 50, duration: '5m' },   // hold — the measurement window
        { target: 150, duration: '2m' },  // push past expected peak
        { target: 150, duration: '3m' },
        { target: 0, duration: '1m' },    // drain
      ],
    },
  },
  thresholds: {
    // p95 on the hold phase is the headline SLO.
    'http_req_duration{expected_response:true}': ['p(95)<500', 'p(99)<1500'],
    // Genuine failures only; 429s are counted separately and excluded below.
    'http_req_failed': ['rate<0.01'],
    'checks': ['rate>0.99'],
    // Throttling above 5% of requests means the limiter is mis-sized for this
    // traffic shape, not that the service is unhealthy — a distinct finding.
    'sephela_rate_limited': ['count<300'],
    'sephela_auth_failures': ['count==0'],
  },
  // Discard response bodies: at 150 rps the generator's own memory becomes the
  // bottleneck otherwise, and nothing here needs the payload.
  discardResponseBodies: false,
};

export function setup() {
  // One login per run, reused by every VU. See lib/session.js on why not per-iteration.
  return { token: login(0) };
}

export default function (data) {
  const auth = authHeaders(data.token);

  group('job list', () => {
    const res = http.get(`${API}/jobs?limit=50`, { ...auth, tags: { name: 'jobs/list' } });
    if (!classify(res, 'list jobs')) return;

    const items = res.json('items') || [];
    if (items.length === 0) return;   // an empty staging DB is not a failure

    // Read one job's detail the way a dashboard drilling in would.
    const jobId = items[Math.floor(Math.random() * items.length)].job_id;

    group('job detail', () => {
      classify(
        http.get(`${API}/jobs/${jobId}`, { ...auth, tags: { name: 'jobs/detail' } }),
        'get job',
      );
      classify(
        http.get(`${API}/jobs/${jobId}/findings?limit=200`, {
          ...auth, tags: { name: 'jobs/findings' },
        }),
        'get findings',
      );
    });
  });

  // Model a dashboard's poll interval rather than hammering as fast as possible —
  // the arrival-rate executor controls throughput, this keeps each VU realistic.
  sleep(1);
}

export function handleSummary(data) {
  const throttled = data.metrics.sephela_rate_limited?.values?.count || 0;
  return {
    stdout: `\nrate-limited responses: ${throttled} (excluded from the error rate)\n`,
    'load-read-summary.json': JSON.stringify(data, null, 2),
  };
}
