import express from "express";
import winston from "winston";
import { parseTrivyReport, extractVulnerabilities, buildSeveritySummary, formatTrivyHumanReadable } from "./reporters/trivyReporter";
import { groupViolationsByCategory, formatOPAHumanReadable, OPAEvaluationResult } from "./reporters/opaReporter";
import { ComplianceReport, OPAViolation } from "./types/report";

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL ?? "info",
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  defaultMeta: { service: "compliance-reporter" },
  transports: [new winston.transports.Console()],
});

const app = express();
const PORT = parseInt(process.env.PORT ?? "8090", 10);

app.use(express.json({ limit: "10mb" }));

/**
 * POST /report
 * Body: { trivyReport: TrivyScanReport, opaResults: OPAEvaluationResult[] }
 * Returns: ComplianceReport
 */
app.post("/report", (req, res) => {
  try {
    const { trivyReport: rawTrivy, opaResults } = req.body as {
      trivyReport: unknown;
      opaResults: OPAEvaluationResult[];
    };

    // Process Trivy data
    const trivyReport = parseTrivyReport(rawTrivy);
    const vulns = extractVulnerabilities(trivyReport);
    const vulnSeverity = buildSeveritySummary(vulns);
    const trivyHumanReadable = formatTrivyHumanReadable(trivyReport, vulns);

    // Process OPA data
    const allViolations: OPAViolation[] = (opaResults ?? []).flatMap((r) => r.violations ?? []);
    const policySummaries = groupViolationsByCategory(allViolations);
    const opaHumanReadable = formatOPAHumanReadable(policySummaries);

    // Compute score
    const totalPolicies = policySummaries.reduce((s, p) => s + p.totalChecks, 0);
    const passedPolicies = policySummaries.reduce((s, p) => s + p.passed, 0);
    const score = totalPolicies > 0 ? Math.round((passedPolicies / totalPolicies) * 100) : 100;

    const hasCriticalOrHigh =
      vulnSeverity.CRITICAL > 0 || vulnSeverity.HIGH > 0 || allViolations.some((v) => v.severity === "CRITICAL" || v.severity === "HIGH");

    const report: ComplianceReport = {
      generatedAt: new Date().toISOString(),
      reportVersion: "1.0.0",
      overallStatus: hasCriticalOrHigh ? "NON_COMPLIANT" : score >= 80 ? "COMPLIANT" : "NON_COMPLIANT",
      score,
      summary: {
        totalPolicies,
        passed: passedPolicies,
        failed: totalPolicies - passedPolicies,
        vulnerabilities: vulnSeverity,
        misconfigurations: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 },
      },
      policies: policySummaries,
      vulnerabilities: vulns,
      humanReadable: [trivyHumanReadable, "", opaHumanReadable].join("\n"),
    };

    logger.info("Compliance report generated", {
      status: report.overallStatus,
      score: report.score,
      criticalVulns: vulnSeverity.CRITICAL,
      highVulns: vulnSeverity.HIGH,
    });

    res.json(report);
  } catch (err) {
    logger.error("Report generation failed", { error: err instanceof Error ? err.message : String(err) });
    res.status(400).json({ error: "Failed to generate report", details: err instanceof Error ? err.message : String(err) });
  }
});

app.get("/healthz", (_req, res) => {
  res.json({ status: "ok", service: "compliance-reporter", timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
  logger.info("compliance-reporter listening", { port: PORT });
});

export default app;
