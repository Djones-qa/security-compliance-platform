import { TrivyScanReport, TrivyVulnerability, SeveritySummary, Severity } from "../types/report";

export function parseTrivyReport(raw: unknown): TrivyScanReport {
  // Basic runtime validation
  if (typeof raw !== "object" || raw === null) {
    throw new Error("Invalid Trivy report: expected object");
  }
  return raw as TrivyScanReport;
}

export function extractVulnerabilities(report: TrivyScanReport): TrivyVulnerability[] {
  const vulns: TrivyVulnerability[] = [];
  for (const result of report.Results) {
    if (result.Vulnerabilities) {
      vulns.push(...result.Vulnerabilities);
    }
  }
  return vulns;
}

export function buildSeveritySummary(vulns: TrivyVulnerability[]): SeveritySummary {
  const summary: SeveritySummary = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
  for (const v of vulns) {
    const sev: Severity = v.Severity ?? "UNKNOWN";
    summary[sev] = (summary[sev] ?? 0) + 1;
  }
  return summary;
}

export function formatTrivyHumanReadable(report: TrivyScanReport, vulns: TrivyVulnerability[]): string {
  const summary = buildSeveritySummary(vulns);
  const lines: string[] = [
    `Trivy Scan Report — ${report.ArtifactName}`,
    `${"=".repeat(60)}`,
    `Scanned: ${report.ArtifactType}`,
    ``,
    `Vulnerability Summary:`,
    `  CRITICAL : ${summary.CRITICAL}`,
    `  HIGH     : ${summary.HIGH}`,
    `  MEDIUM   : ${summary.MEDIUM}`,
    `  LOW      : ${summary.LOW}`,
    `  UNKNOWN  : ${summary.UNKNOWN}`,
    ``,
  ];

  const highAndCritical = vulns.filter((v) => v.Severity === "CRITICAL" || v.Severity === "HIGH");
  if (highAndCritical.length > 0) {
    lines.push("HIGH/CRITICAL Vulnerabilities:");
    for (const v of highAndCritical) {
      lines.push(`  [${v.Severity}] ${v.VulnerabilityID} — ${v.PkgName}@${v.InstalledVersion}`);
      lines.push(`    ${v.Title}`);
      if (v.FixedVersion) lines.push(`    Fixed in: ${v.FixedVersion}`);
    }
  }

  return lines.join("\n");
}
