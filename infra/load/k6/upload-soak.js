// Upload-path load test — the expensive path.
//
// Deliberately a *low-rate soak* rather than a spike test. One upload commits the
// platform to minutes of downstream work (static parse, threat-intel lookups, an
// eight-agent LLM run, possibly an emulator boot), so the interesting question is not
// "how many uploads per second can the endpoint absorb" — the endpoint returns 202
// almost immediately — but "does the queue drain as fast as it fills, and what does
// the API do while it does not".
//
// Read the queue-depth trend, not the request latency, to interpret a run.
//
//   make load-upload SEPHELA_URL=https://api.staging.sephela.example
//
// ⚠️  Run against staging only, and check what is enabled first:
//     * SEPHELA_AI_ENABLED=true spends real money per upload. A 10-minute soak at
//       0.5 uploads/s is ~300 multi-agent runs.
//     * SEPHELA_DYNAMIC_ENABLED=true boots an emulator per upload and will exhaust
//       the KVM node pool long before the API is stressed.
//   Both are best left off unless the run is specifically measuring them.

import http from 'k6/http';
import { Trend } from 'k6/metrics';
import { sleep } from 'k6';
import { API, authHeaders, classify, login, syntheticApk } from './lib/session.js';

// Padding size, in KiB. The default is small on purpose: a realistic 30 MB APK makes
// the run a test of the load generator's uplink. Raise it to measure the upload path
// itself, and expect the ingress body-size limit (300 MiB) to be the ceiling.
const APK_KB = Number(__ENV.SEPHELA_LOAD_APK_KB || 64);

const acceptLatency = new Trend('sephela_upload_accept_ms', true);
const queueDepth = new Trend('sephela_queue_depth');

export const options = {
  scenarios: {
    upload_soak: {
      executor: 'constant-arrival-rate',
      rate: Number(__ENV.SEPHELA_LOAD_UPLOAD_RATE || 30),
      timeUnit: '1m',            // 30/min = one upload every 2s
      duration: __ENV.SEPHELA_LOAD_DURATION || '10m',
      preAllocatedVUs: 5,
      maxVUs: 20,
    },
  },
  thresholds: {
    // The endpoint only has to validate, store, and enqueue — the analysis is
    // asynchronous, so acceptance should stay fast even while the queue is deep.
    // A rising p95 here means storage or the DB commit is the bottleneck.
    'sephela_upload_accept_ms': ['p(95)<2000', 'p(99)<5000'],
    'http_req_failed': ['rate<0.02'],
    'checks': ['rate>0.98'],
    // Uploads have their own tight bucket (20/min by default). Exceeding the
    // configured rate is expected to throttle — that is the control working, so this
    // ceiling is generous and exists only to catch a limiter that rejects everything.
    'sephela_rate_limited': ['count<200'],
  },
};

export function setup() {
  const token = login(0);
  // Record the starting backlog so a run against an already-saturated staging
  // environment is interpretable rather than mysteriously slow.
  return { token, apk: syntheticApk(APK_KB) };
}

export default function (data) {
  const auth = authHeaders(data.token);

  const res = http.post(
    `${API}/uploads`,
    { file: http.file(data.apk, `loadtest-${__VU}-${__ITER}.apk`, 'application/vnd.android.package-archive') },
    { headers: { Authorization: `Bearer ${data.token}` }, tags: { name: 'uploads/post' } },
  );

  if (classify(res, 'upload accepted', 202)) {
    acceptLatency.add(res.timings.duration);
  }

  // Sample the backlog. The API exposes job counts rather than raw queue depth, so
  // "queued jobs" is the proxy — good enough to see whether the pipeline is keeping
  // up, which is the actual question this scenario answers.
  if (__ITER % 10 === 0) {
    const queued = http.get(`${API}/jobs?status=queued&limit=200`, {
      ...auth, tags: { name: 'jobs/queued' },
    });
    if (queued.status === 200) {
      queueDepth.add((queued.json('items') || []).length);
    }
  }

  sleep(1);
}

export function handleSummary(data) {
  const depth = data.metrics.sephela_queue_depth?.values;
  const drained = depth ? `queued jobs: avg ${Math.round(depth.avg)}, max ${depth.max}` : 'queue depth not sampled';
  return {
    stdout:
      `\n${drained}\n` +
      'A max that keeps climbing across the run means the workers are not keeping up ' +
      'with ingest — scale the pools or lower the arrival rate.\n',
    'load-upload-summary.json': JSON.stringify(data, null, 2),
  };
}
