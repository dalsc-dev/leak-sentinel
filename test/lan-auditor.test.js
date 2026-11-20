import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { auditLanExposures } from '../src/lan-auditor.js';

describe('LAN & Localhost Exposure Auditor', () => {
  test('flags high-risk Ollama unauthenticated LLM API on 0.0.0.0:11434', async () => {
    const bindings = [{ port: 11434, host: '0.0.0.0', service: 'Ollama API' }];
    const res = await auditLanExposures({ mockBindings: bindings });
    assert.equal(res.findings.length, 1);
    assert.equal(res.findings[0].severity, 'CRITICAL');
    assert.ok(res.findings[0].title.includes('Ollama API'));
  });

  test('flags high-risk unauthenticated Redis on 0.0.0.0:6379', async () => {
    const bindings = [{ port: 6379, host: '0.0.0.0', service: 'Redis' }];
    const res = await auditLanExposures({ mockBindings: bindings });
    assert.equal(res.findings.length, 1);
    assert.equal(res.findings[0].severity, 'HIGH');
  });

  test('ignores secure localhost-only (127.0.0.1) bindings', async () => {
    const bindings = [
      { port: 3000, host: '127.0.0.1', service: 'Local App' },
      { port: 5432, host: '127.0.0.1', service: 'Postgres' }
    ];
    const res = await auditLanExposures({ mockBindings: bindings });
    assert.equal(res.findings.length, 0);
  });
});
