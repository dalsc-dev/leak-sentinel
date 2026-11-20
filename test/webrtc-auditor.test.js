import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { parseIceCandidate, auditWebRtcCandidates } from '../src/webrtc-auditor.js';

describe('WebRTC ICE Candidate & IP Leak Auditor', () => {
  test('correctly parses candidate lines and extracts IPs and types', () => {
    const cand = 'candidate:1 1 UDP 2130706431 192.168.1.105 54321 typ host';
    const parsed = parseIceCandidate(cand);
    assert.equal(parsed.ip, '192.168.1.105');
    assert.equal(parsed.type, 'host');
    assert.equal(parsed.isPrivateIpv4, true);
    assert.equal(parsed.isMdns, false);
  });

  test('ignores mDNS masked local host candidates', () => {
    const cand = 'candidate:1 1 UDP 2130706431 d8f7a6b2-3c4d-4e5f.local 54321 typ host';
    const parsed = parseIceCandidate(cand);
    assert.equal(parsed.isMdns, true);
    const audit = auditWebRtcCandidates([cand]);
    assert.equal(audit.webrtcDetails.leaksDetected, false);
  });

  test('flags CRITICAL public STUN IP leak (srflx candidate)', () => {
    const candidates = [
      'candidate:1 1 UDP 1694498815 198.51.100.77 54322 typ srflx raddr 192.168.1.105 rport 54321'
    ];
    const audit = auditWebRtcCandidates(candidates);
    assert.equal(audit.webrtcDetails.leaksDetected, true);
    const leak = audit.findings.find(f => f.id === 'WEBRTC_STUN_PUBLIC_IP_LEAK');
    assert.ok(leak);
    assert.equal(leak.severity, 'CRITICAL');
    assert.ok(leak.leakedData.includes('198.51.100.77'));
  });

  test('flags IPv6 global unicast leak', () => {
    const candidates = [
      'candidate:1 1 UDP 1694498815 2001:db8::1234 54322 typ srflx raddr :: rport 54321'
    ];
    const audit = auditWebRtcCandidates(candidates);
    const leak = audit.findings.find(f => f.id === 'WEBRTC_IPV6_BYPASS_LEAK');
    assert.ok(leak);
    assert.equal(leak.severity, 'CRITICAL');
  });
});
