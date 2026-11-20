import { runFullAudit } from '../src/index.js';

async function audit() {
  const report = await runFullAudit();
  console.log(`Security Score: ${report.score}/100 (Grade: ${report.grade})`);
  console.log(`Findings: ${report.findings.length}`);
}

audit();
