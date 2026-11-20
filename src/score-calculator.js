/**
 * score-calculator.js
 * Calculates weighted Privacy Health Score (0 - 100), letter grade, and remediation summary.
 */

export function calculatePrivacyScore(findings = []) {
  let score = 100;

  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;

  for (const f of findings) {
    switch (f.severity) {
      case 'CRITICAL':
        score -= 25;
        criticalCount++;
        break;
      case 'HIGH':
        score -= 15;
        highCount++;
        break;
      case 'MEDIUM':
        score -= 8;
        mediumCount++;
        break;
      case 'LOW':
        score -= 3;
        lowCount++;
        break;
    }
  }

  // Clamp between 0 and 100
  score = Math.max(0, Math.min(100, score));

  let grade = 'F';
  if (score >= 95) grade = 'A+';
  else if (score >= 85) grade = 'A';
  else if (score >= 75) grade = 'B';
  else if (score >= 60) grade = 'C';
  else if (score >= 45) grade = 'D';

  return {
    score,
    grade,
    summary: {
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      totalFindings: findings.length,
      passedCount: Math.max(0, 8 - findings.length)
    }
  };
}

/**
 * Generates an exportable Markdown audit report.
 * @param {import('../index.d.ts').AuditReport} report
 * @returns {string}
 */
export function formatMarkdownReport(report) {
  const lines = [
    `# LeakSentinel Privacy & Network Leak Audit Report`,
    `Generated on: ${report.timestamp}`,
    ``,
    `## Security Score: **${report.score} / 100** (Grade: **${report.grade}**)`,
    ``,
    `| Severity | Count |`,
    `| --- | --- |`,
    `| Critical | ${report.summary.criticalCount} |`,
    `| High | ${report.summary.highCount} |`,
    `| Medium | ${report.summary.mediumCount} |`,
    `| Low | ${report.summary.lowCount} |`,
    ``,
    `## Detailed Findings & Actionable Remediations`,
    ``
  ];

  if (report.findings.length === 0) {
    lines.push(`No network or privacy leaks detected. System is exceptionally well protected.`);
  } else {
    report.findings.forEach((f, idx) => {
      lines.push(`### ${idx + 1}. [${f.severity}] ${f.title}`);
      lines.push(`- **Category**: ${f.category.toUpperCase()}`);
      lines.push(`- **Description**: ${f.description}`);
      if (f.leakedData) {
        lines.push(`- **Exposed Data**: \`${Array.isArray(f.leakedData) ? f.leakedData.join(', ') : f.leakedData}\``);
      }
      lines.push(`- **Remediation**: ${f.remediation}`);
      lines.push(``);
    });
  }

  return lines.join('\n');
}
