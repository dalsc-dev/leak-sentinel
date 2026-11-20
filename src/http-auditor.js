/**
 * http-auditor.js
 * Audits HTTP proxy and client headers for IP address leaks and browser tracking entropy.
 */

// Headers known to leak real client IPs through proxy configurations
const PROXY_LEAK_HEADERS = [
  'x-forwarded-for',
  'client-ip',
  'x-real-ip',
  'via',
  'cf-connecting-ip',
  'true-client-ip',
  'x-cluster-client-ip',
  'forwarded'
];

export function auditHttpHeaders(headers = {}) {
  const findings = [];
  const normalized = {};

  for (const [k, v] of Object.entries(headers)) {
    normalized[k.toLowerCase()] = v;
  }

  const leakedHeaders = [];

  // Check 1: Proxy IP Leakage Headers
  for (const h of PROXY_LEAK_HEADERS) {
    if (normalized[h]) {
      leakedHeaders.push({ header: h, value: normalized[h] });
    }
  }

  if (leakedHeaders.length > 0) {
    findings.push({
      id: 'HTTP_HEADER_CLIENT_IP_LEAK',
      category: 'http',
      severity: 'HIGH',
      title: 'Real Client IP Leaked in HTTP Request Headers',
      description: `Proxy/Gateway is appending upstream headers (${leakedHeaders.map(l => l.header).join(', ')}) revealing the client origin IP address to destination servers.`,
      leakedData: leakedHeaders.map(l => `${l.header}: ${l.value}`),
      remediation: 'Strip or sanitize forward headers (X-Forwarded-For, Via, Client-IP) in reverse proxy / VPN gateway configurations.'
    });
  }

  // Check 2: High Entropy Client Hints (Sec-CH-UA-Model / Sec-CH-UA-Platform-Version)
  const hasHighEntropyHints = !!(normalized['sec-ch-ua-model'] || normalized['sec-ch-ua-platform-version']);
  if (hasHighEntropyHints) {
    findings.push({
      id: 'HTTP_HIGH_ENTROPY_CLIENT_HINTS',
      category: 'http',
      severity: 'LOW',
      title: 'High-Entropy User-Agent Client Hints Exposed',
      description: 'Browser is broadcasting exact device hardware models and micro-kernel OS versions via Sec-CH-UA client hints, increasing device fingerprintability across unrelated domains.',
      leakedData: [
        normalized['sec-ch-ua-model'] ? `sec-ch-ua-model: ${normalized['sec-ch-ua-model']}` : '',
        normalized['sec-ch-ua-platform-version'] ? `sec-ch-ua-platform-version: ${normalized['sec-ch-ua-platform-version']}` : ''
      ].filter(Boolean),
      remediation: 'Use a browser profile or extension that standardizes Client Hints to generic desktop platforms.'
    });
  }

  // Check 3: Global Privacy Control (GPC)
  const hasGpc = normalized['sec-gpc'] === '1';
  if (!hasGpc) {
    findings.push({
      id: 'HTTP_GPC_NOT_ENABLED',
      category: 'http',
      severity: 'LOW',
      title: 'Global Privacy Control (Sec-GPC) Not Broadcasted',
      description: 'Your browser does not send the Sec-GPC: 1 signal. Under CCPA and GDPR, sites are legally required to honor this header to opt out of third-party data selling.',
      remediation: 'Enable "Global Privacy Control" or "Send Do Not Track" in browser privacy settings.'
    });
  }

  return {
    findings,
    httpDetails: {
      leakedHeaders: leakedHeaders.map(l => l.header),
      hasHighEntropyHints,
      hasGpc
    }
  };
}
