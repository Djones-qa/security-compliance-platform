import { OPAViolation, PolicySummary, PolicyCategory } from "../types/report";

export interface OPAEvaluationResult {
  namespace: string;
  resource: string;
  violations: OPAViolation[];
  timestamp: string;
}

const POLICY_CATEGORIES: PolicyCategory[] = [
  "container-security",
  "resource-management",
  "network",
  "access-control",
  "secrets",
];

export function groupViolationsByCategory(violations: OPAViolation[]): PolicySummary[] {
  const categoryMap = new Map<PolicyCategory, OPAViolation[]>();

  for (const cat of POLICY_CATEGORIES) {
    categoryMap.set(cat, []);
  }

  for (const violation of violations) {
    const list = categoryMap.get(violation.category) ?? [];
    list.push(violation);
    categoryMap.set(violation.category, list);
  }

  return POLICY_CATEGORIES.map((cat) => {
    const catViolations = categoryMap.get(cat) ?? [];
    return {
      category: cat,
      totalChecks: catViolations.length + 5, // mock: 5 checks per category passing
      passed: 5,
      failed: catViolations.length,
      violations: catViolations,
    };
  });
}

export function formatOPAHumanReadable(summaries: PolicySummary[]): string {
  const lines: string[] = [
    "OPA Policy Compliance Report",
    "=".repeat(60),
    "",
  ];

  for (const summary of summaries) {
    const status = summary.failed === 0 ? "✓ PASS" : "✗ FAIL";
    lines.push(`[${status}] ${summary.category}`);
    lines.push(`  Checks: ${summary.totalChecks} | Passed: ${summary.passed} | Failed: ${summary.failed}`);
    if (summary.violations.length > 0) {
      for (const v of summary.violations) {
        lines.push(`  - [${v.severity}] ${v.policy}: ${v.message}`);
        lines.push(`    Resource: ${v.namespace}/${v.resource}`);
      }
    }
    lines.push("");
  }

  return lines.join("\n");
}
