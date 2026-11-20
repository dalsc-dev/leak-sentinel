/**
 * webrtc-auditor.js
 * Inspects WebRTC ICE candidates for local LAN topology and STUN public IP exposure leaks.
 */

export function parseIceCandidate(candidateStr) {
  if (!candidateStr || typeof candidateStr !== 'string') return null;

  // Format: candidate:foundation component transport priority ip port typ type [raddr ...]
  const parts = candidateStr.trim().split(/\s+/);
  if (parts.length < 8) return null;

  const ip = parts[4];
  const port = parseInt(parts[5], 10);
  const typeIdx = parts.indexOf('typ');
  const type = typeIdx !== -1 && parts[typeIdx + 1] ? parts[typeIdx + 1] : 'unknown';

  const isIpv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(ip);
  const isIpv6 = ip.includes(':') && !ip.includes('.local');
  const isPrivateIpv4 = isIpv4 && (
    ip.startsWith('10.') ||
    ip.startsWith('192.168.') ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip) ||
    ip.startsWith('127.')
  );

  return {
    raw: candidateStr,
    ip,
    port,
    type, // 'host', 'srflx', 'relay'
    isIpv4,
    isIpv6,
    isPrivateIpv4,
    isMdns: ip.endsWith('.local')
  };
}

export function auditWebRtcCandidates(candidates = []) {
  const findings = [];
  const parsedCandidates = [];
  const exposedIps = new Set();
  let leakedPublicIp = false;
  let leakedPrivateIp = false;
  let leakedIpv6 = false;

  for (const cand of candidates) {
    const parsed = parseIceCandidate(cand);
    if (!parsed) continue;
    parsedCandidates.push(parsed);

    // Skip mDNS masked candidates (e.g. 7f0a823c-1b77-44a6.local)
    if (parsed.isMdns) continue;

    if (parsed.type === 'srflx' || (!parsed.isPrivateIpv4 && !parsed.isMdns)) {
      exposedIps.add(parsed.ip);
      if (parsed.isIpv6) {
        leakedIpv6 = true;
      } else {
        leakedPublicIp = true;
      }
    } else if (parsed.isPrivateIpv4) {
      exposedIps.add(parsed.ip);
      leakedPrivateIp = true;
    }
  }

  // Check 1: STUN Public IP Leak
  if (leakedPublicIp) {
    findings.push({
      id: 'WEBRTC_STUN_PUBLIC_IP_LEAK',
      category: 'webrtc',
      severity: 'CRITICAL',
      title: 'WebRTC STUN Public IP Exposure',
      description: 'WebRTC has gathered server reflexive (srflx) ICE candidates via STUN, exposing your true ISP public IP address directly to visited web pages, bypassing standard browser proxy / VPN configurations.',
      leakedData: Array.from(exposedIps).filter(ip => !ip.startsWith('192.168.') && !ip.startsWith('10.')),
      remediation: 'Disable WebRTC in browser settings (Firefox: set "media.peerconnection.enabled" to false) or use an extension like uBlock Origin with WebRTC IP masking enabled.'
    });
  }

  // Check 2: IPv6 Global Unicast Leak
  if (leakedIpv6) {
    findings.push({
      id: 'WEBRTC_IPV6_BYPASS_LEAK',
      category: 'webrtc',
      severity: 'CRITICAL',
      title: 'WebRTC Global IPv6 Address Leak',
      description: 'WebRTC exposed a globally routable IPv6 address. Many consumer VPNs only tunnel IPv4 traffic, leaving WebRTC IPv6 completely exposed to any web script.',
      leakedData: Array.from(exposedIps).filter(ip => ip.includes(':')),
      remediation: 'Disable IPv6 on your active network interface or switch to a VPN provider that supports dual-stack IPv4/IPv6 tunneling.'
    });
  }

  // Check 3: Private LAN Subnet Exposure
  if (leakedPrivateIp) {
    findings.push({
      id: 'WEBRTC_INTERNAL_LAN_TOPOLOGY_LEAK',
      category: 'webrtc',
      severity: 'MEDIUM',
      title: 'Internal LAN Subnet Topology Exposure',
      description: 'WebRTC host candidates leaked private RFC 1918 LAN IP addresses. Web trackers use internal IP ranges to correlate multiple browser profiles on the same local network.',
      leakedData: Array.from(exposedIps).filter(ip => ip.startsWith('192.168.') || ip.startsWith('10.')),
      remediation: 'Enable mDNS candidate obfuscation in browser flags or disable WebRTC when not conducting voice/video calls.'
    });
  }

  return {
    findings,
    webrtcDetails: {
      leaksDetected: findings.length > 0,
      candidatesCount: parsedCandidates.length,
      exposedIps: Array.from(exposedIps)
    }
  };
}
