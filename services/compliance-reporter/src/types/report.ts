export type Severity = "UNKNOWN" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type PolicyCategory = "container-security" | "resource-management" | "network" | "access-control" | "secrets";

export interface TrivyVulnerability {
  VulnerabilityID: string;
  PkgName: string;
  InstalledVersion: string;
  FixedVersion?: string;
  Severity: Severity;
  Title: string;
  Description?: string;
  CVSS?: Record<string, { V3Score?: number }>;
}

export interface TrivyResult {
  Target: string;
  Class: string;
  Type: string;
  Vulnerabilities?: TrivyVulnerability[];
  Misconfigurations?: Array<{
    ID: string;
    Title: string;
    Severity: Severity;
    Message: string;
    Resolution: string;
  }>;
}

export interface TrivyScanReport {
  SchemaVersion: number;
  ArtifactName: string;
  ArtifactType: string;
  Metadata?: {
    ImageID?: string;
    RepoTags?: string[];
    OS?: { Family: string; Name: string };
  };
  Results: TrivyResult[];
}

export interface OPAViolation {
  policy: string;
  message: string;
  severity: Severity;
  category: PolicyCategory;
  resource: string;
  namespace: string;
}

export interface PolicySummary {
  category: PolicyCategory;
  totalChecks: number;
  passed: number;
  failed: number;
  violations: OPAViolation[];
}

export interface SeveritySummary {
  CRITICAL: number;
  HIGH: number;
  MEDIUM: number;
  LOW: number;
  UNKNOWN: number;
}

export interface ComplianceReport {
  generatedAt: string;
  reportVersion: string;
  overallStatus: "COMPLIANT" | "NON_COMPLIANT" | "UNKNOWN";
  score: number; // 0-100
  summary: {
    totalPolicies: number;
    passed: number;
    failed: number;
    vulnerabilities: SeveritySummary;
    misconfigurations: SeveritySummary;
  };
  policies: PolicySummary[];
  vulnerabilities: TrivyVulnerability[];
  humanReadable: string;
}
