/**
 * lan-auditor.js
 * Scans local network interfaces and checks for high-risk non-loopback (0.0.0.0) service bindings.
 */

import os from 'node:os';

// High-risk developer services commonly bound to 0.0.0.0 accidentally
export const KNOWN_SENSITIVE_PORTS = {
  11434: { service: 'Ollama API', risk: 'CRITICAL', reason: 'Unauthenticated local LLM execution and model theft' },
  2375:  { service: 'Docker Daemon (Plaintext)', risk: 'CRITICAL', reason: 'Unauthenticated root container execution' },
  6379:  { service: 'Redis Server', risk: 'HIGH', reason: 'In-memory database frequently deployed without authentication' },
  27017: { service: 'MongoDB', risk: 'HIGH', reason: 'Database exposed to local network neighbors' },
  5432:  { service: 'PostgreSQL', risk: 'HIGH', reason: 'Relational database port reachable over LAN' },
  3306:  { service: 'MySQL / MariaDB', risk: 'HIGH', reason: 'Exposed SQL database service' },
  9200:  { service: 'Elasticsearch', risk: 'HIGH', reason: 'Unauthenticated cluster search and indexing' },
  8080:  { service: 'Dev HTTP Server', risk: 'MEDIUM', reason: 'Development web server exposed to LAN' },
  3000:  { service: 'Node / React Dev Server', risk: 'MEDIUM', reason: 'Frontend hot-reload server exposed to Wi-Fi' },
  5173:  { service: 'Vite Dev Server', risk: 'MEDIUM', reason: 'Vite local dev server bound publicly' }
};

export async function auditLanExposures(options = {}) {
  const findings = [];
  const networkInterfaces = os.networkInterfaces();
  const nonLoopbackIps = [];

  // Enumerate active non-loopback IP addresses
  for (const [ifaceName, ifaceDetails] of Object.entries(networkInterfaces)) {
    if (!ifaceDetails) continue;
    for (const addr of ifaceDetails) {
      if (!addr.internal && addr.family === 'IPv4') {
        nonLoopbackIps.push({ iface: ifaceName, address: addr.address });
      }
    }
  }

  const bindings = options.mockBindings || [];

  for (const b of bindings) {
    const isExposed = b.host === '0.0.0.0' || b.host === '::' || nonLoopbackIps.some(ip => ip.address === b.host);
    if (!isExposed) continue;

    const sensitiveInfo = KNOWN_SENSITIVE_PORTS[b.port];
    const serviceName = sensitiveInfo ? sensitiveInfo.service : (b.service || `Port ${b.port}`);
    const severity = sensitiveInfo ? sensitiveInfo.risk : 'MEDIUM';

    findings.push({
      id: `LAN_EXPOSURE_${b.port}`,
      category: 'lan',
      severity,
      title: `Exposed ${serviceName} on 0.0.0.0:${b.port}`,
      description: `Service "${serviceName}" is bound to all network interfaces (0.0.0.0:${b.port}). Anyone on the same Wi-Fi / LAN network can communicate directly with this service without going through localhost. ${sensitiveInfo ? sensitiveInfo.reason : ''}`,
      leakedData: `${b.host}:${b.port}`,
      remediation: `Rebind the service strictly to localhost: "127.0.0.1:${b.port}" (e.g. in Docker: "-p 127.0.0.1:${b.port}:${b.port}").`
    });
  }

  return {
    findings,
    lanDetails: {
      exposedServices: bindings.map(b => ({
        port: b.port,
        host: b.host,
        service: KNOWN_SENSITIVE_PORTS[b.port]?.service || b.service || `Port ${b.port}`,
        severity: KNOWN_SENSITIVE_PORTS[b.port]?.risk || 'MEDIUM'
      })),
      interfacesCount: nonLoopbackIps.length,
      activeInterfaces: nonLoopbackIps
    }
  };
}
