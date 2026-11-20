#!/usr/bin/env node

/**
 * bin/probe.js
 * leak-probe CLI - Companion lightweight leak checker for CI/CD and pre-commit hooks.
 */

import { runFullAudit } from '../src/index.js';

async function main() {
  const args = process.argv.slice(2);
  const jsonMode = args.includes('-j') || args.includes('--json');
  const failOnLeak = args.includes('--fail-on-leak');

  const report = await runFullAudit();

  if (jsonMode) {
    console.log(JSON.stringify({
      score: report.score,
      grade: report.grade,
      criticalLeaks: report.summary.criticalCount,
      highLeaks: report.summary.highCount,
      leaksDetected: report.findings.length > 0,
      timestamp: report.timestamp
    }));
  } else {
    console.log(`[leak-probe] Privacy Score: ${report.score}/100 (${report.grade}) | Findings: ${report.findings.length}`);
    if (report.findings.length > 0) {
      report.findings.forEach(f => {
        console.log(`  - [${f.severity}] ${f.title}`);
      });
    }
  }

  if (failOnLeak && (report.summary.criticalCount > 0 || report.summary.highCount > 0)) {
    process.exit(1);
  }
}

main().catch(err => {
  console.error('[leak-probe error]', err.message);
  process.exit(1);
});
