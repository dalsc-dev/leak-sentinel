/**
 * index.js
 * Main entry point for the leak-sentinel privacy & network leak audit suite.
 */

import { auditDns } from './dns-auditor.js';
import { auditWebRtcCandidates } from './webrtc-auditor.js';
import { auditLanExposures } from './lan-auditor.js';
import { auditHttpHeaders } from './http-auditor.js';
import { auditFingerprintEntropy } from './fingerprint-auditor.js';
import { calculatePrivacyScore, formatMarkdownReport } from './score-calculator.js';

export {
  auditDns,
  auditWebRtcCandidates,
  auditLanExposures,
  auditHttpHeaders,
  auditFingerprintEntropy,
  calculatePrivacyScore,
  formatMarkdownReport
};
export { createAuditServer, createRequestHandler } from './server.js';

/**
 * Runs a comprehensive 5-vector privacy and network leak audit.
 * @param {object} [options]
 * @returns {Promise<import('../index.d.ts').AuditReport>}
 */
export async function runFullAudit(options = {}) {
  const dnsRes = await auditDns(options.dnsOptions || {});
  const lanRes = await auditLanExposures(options.lanOptions || {});
  const webrtcRes = auditWebRtcCandidates(options.webrtcCandidates || []);
  const httpRes = auditHttpHeaders(options.customHeaders || {});
  const fpRes = auditFingerprintEntropy(options.fingerprintMetrics || {});

  const allFindings = [
    ...dnsRes.findings,
    ...lanRes.findings,
    ...webrtcRes.findings,
    ...httpRes.findings,
    ...fpRes.findings
  ];

  const scoreData = calculatePrivacyScore(allFindings);

  return {
    score: scoreData.score,
    grade: scoreData.grade,
    timestamp: new Date().toISOString(),
    summary: scoreData.summary,
    findings: allFindings,
    dns: dnsRes.dnsDetails,
    lan: lanRes.lanDetails,
    webrtc: webrtcRes.webrtcDetails,
    http: httpRes.httpDetails,
    fingerprint: fpRes.fingerprintDetails
  };
}
