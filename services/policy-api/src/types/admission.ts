export interface AdmissionReviewRequest {
  apiVersion: string;
  kind: "AdmissionReview";
  request: {
    uid: string;
    kind: {
      group: string;
      version: string;
      kind: string;
    };
    resource: {
      group: string;
      version: string;
      resource: string;
    };
    name: string;
    namespace: string;
    operation: "CREATE" | "UPDATE" | "DELETE" | "CONNECT";
    object: Record<string, unknown>;
    oldObject?: Record<string, unknown>;
    userInfo: {
      username: string;
      uid: string;
      groups: string[];
    };
  };
}

export interface AdmissionReviewResponse {
  apiVersion: string;
  kind: "AdmissionReview";
  response: {
    uid: string;
    allowed: boolean;
    status?: {
      code: number;
      message: string;
    };
    auditAnnotations?: Record<string, string>;
  };
}

export interface OPAQueryResult {
  result: {
    allow: boolean;
    deny: string[];
    violations?: Array<{
      policy: string;
      message: string;
      severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
    }>;
  };
}

export interface AuditLogEntry {
  timestamp: string;
  requestId: string;
  namespace: string;
  resource: string;
  operation: string;
  user: string;
  allowed: boolean;
  violations: string[];
  durationMs: number;
}
