import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { auditDns } from '../src/dns-auditor.js';

describe('DNS Leak Auditor', () => {
  test('flags unencrypted local gateway DNS resolver', async () => {
    const res = await auditDns({ mockServers: ['192.168.1.1'] });
    assert.equal(res.dnsDetails.isEncrypted, false);
    const finding = res.findings.find(f => f.id === 'DNS_LEAK_LOCAL_GATEWAY');
    assert.ok(finding);
    assert.equal(finding.severity, 'HIGH');
  });

  test('flags split-tunnel multi-homed DNS leak when both local and public resolvers present', async () => {
    const res = await auditDns({ mockServers: ['192.168.1.1', '1.1.1.1'] });
    assert.equal(res.dnsDetails.hasSplitDnsLeak, true);
    const splitFinding = res.findings.find(f => f.id === 'DNS_LEAK_SPLIT_TUNNEL');
    assert.ok(splitFinding);
    assert.equal(splitFinding.severity, 'CRITICAL');
  });

  test('passes clean when only encrypted privacy DNS resolver is configured', async () => {
    const res = await auditDns({ mockServers: ['9.9.9.9', '149.112.112.112'] });
    assert.equal(res.dnsDetails.isEncrypted, true);
    assert.equal(res.dnsDetails.hasSplitDnsLeak, false);
    const localLeak = res.findings.find(f => f.id === 'DNS_LEAK_LOCAL_GATEWAY');
    assert.equal(localLeak, undefined);
  });
});
