#!/usr/bin/env node

/**
 * bin/cli.js
 * leak-sentinel CLI - Terminal privacy & network leak audit engine.
 */

import { runFullAudit } from '../src/index.js';
import { createAuditServer } from '../src/server.js';

const VERSION = '1.0.0';

const HELP_TEXT = `
\x1b[1m\x1b[32mleak-sentinel\x1b[0m v${VERSION}
Zero-knowledge privacy & network leak audit engine for developers, VPN users, and security engineers.

\x1b[1mUSAGE:\x1b[0m
  $ leak-sentinel [options]
  $ leak-sentinel --web
  $ leak-sentinel --fail-on-leak

\x1b[1mOPTIONS:\x1b[0m
  -w, --web               Launch interactive dark-mode web dashboard
  -p, --port <number>     Web dashboard port (default: 8899)
      --fail-on-leak      Exit with status code 1 if CRITICAL or HIGH leaks are detected
  -j, --json              Output machine-readable JSON report
  -q, --quiet             Suppress banner and summary text
  -h, --help              Show this help screen
  -V, --version           Show version information

\x1b[1mAUDIT VECTORS:\x1b[0m
  • DNS Leaks: Unencrypted local gateway DNS, split-tunnel multi-homing (SMHNR)
  • WebRTC Leaks: STUN server reflexive public IP leaks, IPv6 bypass, internal LAN topology
  • LAN Exposure: Sensitive developer services bound to 0.0.0.0 (Ollama, Docker, Redis, DBs)
  • HTTP Headers: Upstream proxy IP leak headers (X-Forwarded-For, Client-IP, Via)
  • Fingerprint: WebGL hardware renderer, Canvas 2D determinism, font entropy
`;

async function main() {
  const args = process.argv.slice(2);

  if (args.includes('-h') || args.includes('--help')) {
    console.log(HELP_TEXT);
    process.exit(0);
  }

  if (args.includes('-V') || args.includes('--version')) {
    console.log(`leak-sentinel v${VERSION}`);
    process.exit(0);
  }

  const jsonMode = args.includes('-j') || args.includes('--json');
  const webMode = args.includes('-w') || args.includes('--web');
  const failOnLeak = args.includes('--fail-on-leak');
  const quiet = args.includes('-q') || args.includes('--quiet');

  let port = 8899;
  const portIdx = args.findIndex(a => a === '-p' || a === '--port');
  if (portIdx !== -1 && args[portIdx + 1]) {
    port = parseInt(args[portIdx + 1], 10) || 8899;
  }

  // Run initial audit
  const report = await runFullAudit();

  if (jsonMode) {
    console.log(JSON.stringify(report, null, 2));
    if (failOnLeak && (report.summary.criticalCount > 0 || report.summary.highCount > 0)) {
      process.exit(1);
    }
    return;
  }

  if (!quiet) {
    renderTerminalReport(report);
  }

  if (webMode) {
    let currentReport = report;
    const { url } = await createAuditServer(() => currentReport, {
      port,
      openBrowser: true,
      onRecheck: async () => {
        currentReport = await runFullAudit();
        return currentReport;
      },
      onWebrtcUpdate: async (candidates) => {
        currentReport = await runFullAudit({ webrtcCandidates: candidates });
        return currentReport;
      }
    });

    console.log(`\n  \x1b[1mWeb Dashboard:\x1b[0m \x1b[4m\x1b[32m${url}\x1b[0m`);
    console.log('  \x1b[2mPress Ctrl+C to close.\x1b[0m\n');
  } else if (failOnLeak) {
    if (report.summary.criticalCount > 0 || report.summary.highCount > 0) {
      console.error('\n\x1b[31m[GATE FAILED]\x1b[0m Critical or high severity privacy leaks detected.');
      process.exit(1);
    }
  }
}

function renderTerminalReport(report) {
  console.log(`
\x1b[32m  _                _     ____             _   _            _ \x1b[0m
\x1b[32m | |    ___  __ _| | __/ ___|  ___ _ __ | |_(_)_ __   ___| |\x1b[0m
\x1b[32m | |   / _ \\/ _\` | |/ /\\___ \\ / _ \\ '_ \\| __| | '_ \\ / _ \\ |\x1b[0m
\x1b[32m | |__|  __/ (_| |   <  ___) |  __/ | | | |_| | | | |  __/ |\x1b[0m
\x1b[32m |_____\\___|\\__,_|_|\\_\\|____/ \\___|_| |_|\\__|_|_| |_|\\___|_|\x1b[0m

  \x1b[1mPrivacy Health Score:\x1b[0m \x1b[1m\x1b[32m${report.score} / 100\x1b[0m (Grade: \x1b[1m\x1b[36m${report.grade}\x1b[0m)
  \x1b[1mAudit Timestamp:\x1b[0m      ${report.timestamp}
  \x1b[1mFindings Summary:\x1b[0m      ${report.summary.criticalCount} Critical | ${report.summary.highCount} High | ${report.summary.mediumCount} Medium | ${report.summary.passedCount} Passed
`);

  if (report.findings.length === 0) {
    console.log('  \x1b[32m✓ Excellent! Zero privacy leaks or exposed services detected.\x1b[0m\n');
    return;
  }

  console.log('\x1b[1mDetected Vulnerabilities & Remediations:\x1b[0m\n');

  report.findings.forEach((f, idx) => {
    const color = f.severity === 'CRITICAL' ? '\x1b[31m' :
                  f.severity === 'HIGH' ? '\x1b[33m' :
                  f.severity === 'MEDIUM' ? '\x1b[35m' : '\x1b[36m';

    console.log(`  ${idx + 1}. ${color}[${f.severity}]\x1b[0m \x1b[1m${f.title}\x1b[0m`);
    console.log(`     ${f.description}`);
    if (f.leakedData) {
      console.log(`     \x1b[2mExposed:\x1b[0m \x1b[31m${Array.isArray(f.leakedData) ? f.leakedData.join(', ') : f.leakedData}\x1b[0m`);
    }
    console.log(`     \x1b[32mFix:\x1b[0m ${f.remediation}\n`);
  });
}

main().catch(err => {
  console.error('\x1b[31mFatal error:\x1b[0m', err);
  process.exit(1);
});
