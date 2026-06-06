import { Router, Request, Response } from "express";
import axios from "axios";
import { logger } from "../middleware/logger";
import {
  AdmissionReviewRequest,
  AdmissionReviewResponse,
  OPAQueryResult,
  AuditLogEntry,
} from "../types/admission";

export const admissionRouter = Router();

const OPA_URL = process.env.OPA_URL ?? "http://opa:8181";
const OPA_POLICY_PATH = process.env.OPA_POLICY_PATH ?? "/v1/data/kubernetes/admission";

admissionRouter.post("/validate", async (req: Request, res: Response): Promise<void> => {
  const startTime = Date.now();
  const admissionReview = req.body as AdmissionReviewRequest;

  if (!admissionReview?.request) {
    res.status(400).json({ error: "Invalid AdmissionReview request" });
    return;
  }

  const { uid, namespace, operation, object, userInfo } = admissionReview.request;
  const resourceKind = admissionReview.request.kind.kind;

  try {
    // Query OPA for policy decision
    const opaResponse = await axios.post<OPAQueryResult>(
      `${OPA_URL}${OPA_POLICY_PATH}`,
      { input: admissionReview.request },
      {
        headers: { "Content-Type": "application/json" },
        timeout: 5000,
      }
    );

    const { allow, deny, violations = [] } = opaResponse.data.result;
    const durationMs = Date.now() - startTime;

    // Build audit log
    const auditEntry: AuditLogEntry = {
      timestamp: new Date().toISOString(),
      requestId: uid,
      namespace: namespace ?? "cluster-scoped",
      resource: resourceKind,
      operation,
      user: userInfo.username,
      allowed: allow,
      violations: deny,
      durationMs,
    };

    logger.info("Admission decision", auditEntry);

    // Build AdmissionReview response
    const response: AdmissionReviewResponse = {
      apiVersion: "admission.k8s.io/v1",
      kind: "AdmissionReview",
      response: {
        uid,
        allowed: allow,
        auditAnnotations: {
          "policy-api/violations": deny.join("; "),
          "policy-api/duration-ms": String(durationMs),
        },
      },
    };

    if (!allow && deny.length > 0) {
      response.response.status = {
        code: 403,
        message: `Policy violations: ${deny.join("; ")}`,
      };
    }

    res.json(response);
  } catch (err) {
    const durationMs = Date.now() - startTime;
    logger.error("OPA query failed", {
      uid,
      namespace,
      resourceKind,
      error: err instanceof Error ? err.message : String(err),
      durationMs,
    });

    // Fail open on OPA unavailability (configurable)
    const failOpen = process.env.FAIL_OPEN === "true";

    const response: AdmissionReviewResponse = {
      apiVersion: "admission.k8s.io/v1",
      kind: "AdmissionReview",
      response: {
        uid,
        allowed: failOpen,
        status: failOpen
          ? undefined
          : {
              code: 503,
              message: "Policy engine unavailable — request denied for safety",
            },
      },
    };

    res.status(failOpen ? 200 : 503).json(response);
  }
});

admissionRouter.get("/healthz", (_req: Request, res: Response): void => {
  res.json({ status: "ok", service: "policy-api", timestamp: new Date().toISOString() });
});
