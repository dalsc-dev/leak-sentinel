import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { Readable, Writable } from 'node:stream';
import { createRequestHandler } from '../src/server.js';

class MockResponse extends Writable {
  constructor() {
    super();
    this.statusCode = 200;
    this.headers = {};
    this.body = '';
  }

  setHeader(name, val) {
    this.headers[name.toLowerCase()] = val;
  }

  writeHead(status, headers = {}) {
    this.statusCode = status;
    for (const [k, v] of Object.entries(headers)) {
      this.headers[k.toLowerCase()] = v;
    }
  }

  _write(chunk, encoding, callback) {
    this.body += chunk.toString();
    callback();
  }
}

function createMockRequest(method, url, body = null) {
  const req = new Readable({
    read() {
      if (body) {
        this.push(JSON.stringify(body));
      }
      this.push(null);
    }
  });
  req.method = method;
  req.url = url;
  req.headers = { host: 'localhost:8899' };
  return req;
}

describe('Audit Server REST API & Request Handling', () => {
  const mockReport = {
    score: 95,
    grade: 'A+',
    timestamp: '2026-11-20T12:00:00Z',
    summary: { criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0 },
    findings: []
  };

  test('serves web UI on root /', async () => {
    const handler = createRequestHandler(
      () => mockReport,
      () => mockReport,
      null,
      '<html><body>LeakSentinel Dashboard</body></html>'
    );

    const req = createMockRequest('GET', '/');
    const res = new MockResponse();

    await handler(req, res);
    assert.equal(res.statusCode, 200);
    assert.ok(res.headers['content-type'].includes('text/html'));
    assert.ok(res.body.includes('LeakSentinel Dashboard'));
  });

  test('returns JSON audit report on /api/audit', async () => {
    const handler = createRequestHandler(() => mockReport, () => mockReport, null, '');

    const req = createMockRequest('GET', '/api/audit');
    const res = new MockResponse();

    await handler(req, res);
    assert.equal(res.statusCode, 200);
    assert.ok(res.headers['content-type'].includes('application/json'));
    const parsed = JSON.parse(res.body);
    assert.equal(parsed.score, 95);
    assert.equal(parsed.grade, 'A+');
  });

  test('serves markdown file export on /api/export', async () => {
    const handler = createRequestHandler(() => mockReport, () => mockReport, null, '');

    const req = createMockRequest('GET', '/api/export');
    const res = new MockResponse();

    await handler(req, res);
    assert.equal(res.statusCode, 200);
    assert.ok(res.headers['content-type'].includes('text/markdown'));
    assert.ok(res.body.includes('# LeakSentinel'));
  });

  test('receives and processes browser WebRTC candidates via POST /api/webrtc-candidates', async () => {
    let received = null;
    const handler = createRequestHandler(
      () => mockReport,
      () => mockReport,
      async (cands) => { received = cands; },
      ''
    );

    const candidates = ['candidate:1 1 UDP 2130706431 192.168.1.1 5000 typ host'];
    const req = createMockRequest('POST', '/api/webrtc-candidates', { candidates });
    const res = new MockResponse();

    await handler(req, res);

    assert.equal(res.statusCode, 200);
    assert.deepEqual(received, candidates);
  });
});
