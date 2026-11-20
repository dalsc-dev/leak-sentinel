import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { auditHttpHeaders } from '../src/http-auditor.js';

describe('HTTP Headers & Anonymity Auditor', () => {
  test('detects client origin IP leaks in proxy headers', () => {
    const headers = {
      'host': 'example.com',
      'x-forwarded-for': '203.0.113.195',
      'via': '1.1 proxy.internal'
    };
    const res = auditHttpHeaders(headers);
    assert.equal(res.findings.length >= 1, true);
    const ipLeak = res.findings.find(f => f.id === 'HTTP_HEADER_CLIENT_IP_LEAK');
    assert.ok(ipLeak);
    assert.equal(ipLeak.severity, 'HIGH');
  });

  test('detects high entropy client hints', () => {
    const headers = {
      'sec-ch-ua-model': 'MacBookPro18,1',
      'sec-ch-ua-platform-version': '14.5.0'
    };
    const res = auditHttpHeaders(headers);
    const hintFinding = res.findings.find(f => f.id === 'HTTP_HIGH_ENTROPY_CLIENT_HINTS');
    assert.ok(hintFinding);
    assert.equal(hintFinding.severity, 'LOW');
  });

  test('verifies clean headers with Global Privacy Control enabled', () => {
    const headers = {
      'host': 'example.com',
      'sec-gpc': '1'
    };
    const res = auditHttpHeaders(headers);
    const gpcFinding = res.findings.find(f => f.id === 'HTTP_GPC_NOT_ENABLED');
    assert.equal(gpcFinding, undefined);
  });
});
