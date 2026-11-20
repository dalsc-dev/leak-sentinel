/**
 * dns-auditor.js
 * Inspects system DNS resolvers, detects unencrypted query fallbacks and split-tunnel leaks.
 */

import dns from 'node:dns';

// Known privacy-respecting zero-log DNS resolvers
const PRIVACY_RESOLVERS = {
  '9.9.9.9': { name: 'Quad9 (Zero-Log, Threat Blocking)', encryptedSupported: true, score: 95 },
  '149.112.112.112': { name: 'Quad9 Secondary', encryptedSupported: true, score: 95 },
  '1.1.1.1': { name: 'Cloudflare Privacy DNS', encryptedSupported: true, score: 90 },
  '1.0.0.1': { name: 'Cloudflare Secondary', encryptedSupported: true, score: 90 },
  '194.242.2.2': { name: 'Mullvad Zero-Log DoH', encryptedSupported: true, score: 100 },
  '94.140.14.14': { name: 'AdGuard Privacy DNS', encryptedSupported: true, score: 90 },
  '8.8.8.8': { name: 'Google Public DNS', encryptedSupported: true, score: 75 },
  '8.8.4.4': { name: 'Google Public DNS Secondary', encryptedSupported: true, score: 75 }
};

export async function auditDns(options = {}) {
  const findings = [];
  let servers = [];

  try {
    servers = options.mockServers || dns.getServers();
  } catch {
    servers = ['192.168.1.1'];
  }

  let isPrivacyProvider = false;
  let providerName = 'Unknown / Local Gateway';
  let hasLocalGatewayDns = false;
  let hasPublicDns = false;

  for (const server of servers) {
    if (PRIVACY_RESOLVERS[server]) {
      isPrivacyProvider = true;
      providerName = PRIVACY_RESOLVERS[server].name;
      hasPublicDns = true;
    } else if (server.startsWith('192.168.') || server.startsWith('10.') || server.startsWith('172.16.') || server === '127.0.0.1') {
      hasLocalGatewayDns = true;
      providerName = `Local Gateway / Router (${server})`;
    } else {
      hasPublicDns = true;
      providerName = `ISP / Custom Public DNS (${server})`;
    }
  }

  // Check 1: Unencrypted Local Gateway DNS Leak
  if (hasLocalGatewayDns) {
    findings.push({
      id: 'DNS_LEAK_LOCAL_GATEWAY',
      category: 'dns',
      severity: 'HIGH',
      title: 'Unencrypted Local Gateway DNS Resolution',
      description: `DNS queries are routed to local router/gateway (${servers.filter(s => s.startsWith('192.168.') || s.startsWith('10.')).join(', ')}). Your ISP can monitor every domain you visit in cleartext over UDP port 53.`,
      leakedData: servers,
      remediation: 'Configure DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) using Quad9 (9.9.9.9) or Mullvad (194.242.2.2).'
    });
  }

  // Check 2: Split-Tunnel Multi-Homed DNS Leak (SMHNR)
  if (hasLocalGatewayDns && hasPublicDns) {
    findings.push({
      id: 'DNS_LEAK_SPLIT_TUNNEL',
      category: 'dns',
      severity: 'CRITICAL',
      title: 'Split-Tunnel Multi-Homed DNS Leak (SMHNR Risk)',
      description: 'System has both local network and public/VPN resolvers configured simultaneously. Operating systems (especially Windows and macOS) frequently query both interfaces simultaneously, leaking destination domains outside the VPN tunnel.',
      leakedData: servers,
      remediation: 'Enforce exclusive DNS tunneling in your VPN client settings and disable Windows Smart Multi-Homed Name Resolution.'
    });
  }

  // Check 3: Cleartext UDP Port 53 Protocol
  if (!isPrivacyProvider && servers.length > 0) {
    findings.push({
      id: 'DNS_CLEARTEXT_PORT_53',
      category: 'dns',
      severity: 'MEDIUM',
      title: 'Standard Cleartext DNS Protocol In Use',
      description: 'System is sending DNS queries over standard unencrypted UDP port 53 without cryptographic verification (DNSSEC) or encryption (DoH/DoT).',
      leakedData: servers,
      remediation: 'Enable system-wide encrypted DNS in OS settings or via dnscrypt-proxy / stubby.'
    });
  }

  return {
    findings,
    dnsDetails: {
      resolvers: servers,
      isEncrypted: isPrivacyProvider && !hasLocalGatewayDns,
      provider: providerName,
      hasSplitDnsLeak: hasLocalGatewayDns && hasPublicDns
    }
  };
}
