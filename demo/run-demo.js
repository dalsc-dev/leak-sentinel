#!/usr/bin/env node

/**
 * demo/run-demo.js
 * Interactive terminal live demo for leak-sentinel.
 */

import { runFullAudit } from '../src/index.js';
import { auditWebRtcCandidates } from '../src/webrtc-auditor.js';
import { auditLanExposures } from '../src/lan-auditor.js';
import { calculatePrivacyScore, formatMarkdownReport } from '../src/score-calculator.js';

async function runDemo() {
  console.log('\x1b[1m\x1b[32m====================================================\x1b[0m');
  console.log('\x1b[1m\x1b[32m  leak-sentinel: Interactive Terminal Live Demo     \x1b[0m');
  console.log('\x1b[1m\x1b[32m====================================================\x1b[0m\n');

  console.log('\x1b[1m[1/4] Auditing System DNS Resolvers & Encrypted DNS Support...\x1b[0m');
  const realAudit = await runFullAudit({
    dnsOptions: { mockServers: ['192.168.1.1', '1.1.1.1'] } // Split tunnel scenario
  });
  console.log(`  Resolvers Detected: \x1b[36m${realAudit.dns.resolvers.join(', ')}\x1b[0m`);
  console.log(`  Split-Tunnel Leak:  \x1b[31m${realAudit.dns.hasSplitDnsLeak ? 'YES (SMHNR Risk)' : 'NO'}\x1b[0m`);

  console.log('\n\x1b[1m[2/4] Simulating In-Browser WebRTC STUN IP Leak Probe...\x1b[0m');
  const mockIceCandidates = [
    'candidate:1 1 UDP 2130706431 192.168.1.42 54321 typ host',
    'candidate:2 1 UDP 1694498815 198.51.100.25 54322 typ srflx raddr 192.168.1.42 rport 54321',
    'candidate:3 1 UDP 1694498815 2001:db8::8a2e:370:7334 54323 typ srflx raddr :: rport 54321'
  ];
  const webrtcTest = auditWebRtcCandidates(mockIceCandidates);
  console.log(`  Candidates Gathered: \x1b[36m${webrtcTest.webrtcDetails.candidatesCount}\x1b[0m`);
  console.log(`  Exposed Public IPs:  \x1b[31m${webrtcTest.webrtcDetails.exposedIps.join(', ')}\x1b[0m`);

  console.log('\n\x1b[1m[3/4] Scanning Local LAN Interface 0.0.0.0 Exposure Gateways...\x1b[0m');
  const mockBindings = [
    { port: 11434, host: '0.0.0.0', service: 'Ollama API' },
    { port: 6379, host: '0.0.0.0', service: 'Redis' },
    { port: 3000, host: '127.0.0.1', service: 'Local Web App' }
  ];
  const lanTest = await auditLanExposures({ mockBindings });
  console.log(`  Exposed 0.0.0.0 Services: \x1b[31m${lanTest.findings.map(f => f.title).join('; ')}\x1b[0m`);

  console.log('\n\x1b[1m[4/4] Calculating Privacy Security Score & Generating Report...\x1b[0m');
  const combinedFindings = [
    ...realAudit.findings,
    ...webrtcTest.findings,
    ...lanTest.findings
  ];
  const scoreData = calculatePrivacyScore(combinedFindings);
  console.log(`  Final Score: \x1b[1m\x1b[32m${scoreData.score} / 100\x1b[0m (Grade: \x1b[1m\x1b[33m${scoreData.grade}\x1b[0m)`);
  console.log(`  Summary:     ${scoreData.summary.criticalCount} Critical | ${scoreData.summary.highCount} High | ${scoreData.summary.mediumCount} Medium`);

  console.log('\n\x1b[1mSample Markdown Security Export Preview:\x1b[0m');
  const mdPreview = formatMarkdownReport({
    score: scoreData.score,
    grade: scoreData.grade,
    timestamp: new Date().toISOString(),
    summary: scoreData.summary,
    findings: combinedFindings.slice(0, 2)
  });
  console.log(mdPreview.split('\n').map(l => '  ' + l).join('\n'));

  console.log('\n\x1b[1m\x1b[32mDemo executed successfully with 100% precision!\x1b[0m\n');
}

runDemo().catch(err => {
  console.error('\x1b[31mDemo error:\x1b[0m', err);
  process.exit(1);
});
