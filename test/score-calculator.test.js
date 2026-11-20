import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { calculatePrivacyScore, formatMarkdownReport } from '../src/score-calculator.js';

describe('Score Calculator & Markdown Exporter', () => {
  test('calculates perfect 100 A+ score when zero findings present', () => {
    const res = calculatePrivacyScore([]);
    assert.equal(res.score, 100);
    assert.equal(res.grade, 'A+');
    assert.equal(res.summary.criticalCount, 0);
  });

  test('penalizes accurately based on severity weights', () => {
    const findings = [
      { id: 'F1', severity: 'CRITICAL', title: 'Critical Leak' },
      { id: 'F2', severity: 'HIGH', title: 'High Leak' }
    ];
    // 100 - 25 - 15 = 60
    const res = calculatePrivacyScore(findings);
    assert.equal(res.score, 60);
    assert.equal(res.grade, 'C');
    assert.equal(res.summary.criticalCount, 1);
    assert.equal(res.summary.highCount, 1);
  });

  test('clamps minimum score to 0 and assigns F grade', () => {
    const findings = [
      { id: 'F1', severity: 'CRITICAL', title: 'Crit 1' },
      { id: 'F2', severity: 'CRITICAL', title: 'Crit 2' },
      { id: 'F3', severity: 'CRITICAL', title: 'Crit 3' },
      { id: 'F4', severity: 'CRITICAL', title: 'Crit 4' },
      { id: 'F5', severity: 'CRITICAL', title: 'Crit 5' }
    ];
    const res = calculatePrivacyScore(findings);
    assert.equal(res.score, 0);
    assert.equal(res.grade, 'F');
  });

  test('formats structured markdown export', () => {
    const md = formatMarkdownReport({
      score: 85,
      grade: 'A',
      timestamp: '2026-11-20T12:00:00Z',
      summary: { criticalCount: 0, highCount: 1, mediumCount: 0, lowCount: 0 },
      findings: [
        {
          id: 'TEST_FINDING',
          severity: 'HIGH',
          category: 'dns',
          title: 'Test Title',
          description: 'Test Desc',
          remediation: 'Test Fix'
        }
      ]
    });

    assert.ok(md.includes('# LeakSentinel Privacy & Network Leak Audit Report'));
    assert.ok(md.includes('85 / 100'));
    assert.ok(md.includes('[HIGH] Test Title'));
  });
});
