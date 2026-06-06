# Security Compliance Platform

[![CI](https://github.com/Djones-qa/security-compliance-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/Djones-qa/security-compliance-platform/actions/workflows/ci.yml)
[![OPA](https://img.shields.io/badge/OPA-0.59.0-7D3E9A?logo=openpolicyagent&logoColor=white)](https://www.openpolicyagent.org/)
[![Trivy](https://img.shields.io/badge/Trivy-latest-1904DA?logo=aquasecurity&logoColor=white)](https://trivy.dev/)
[![Falco](https://img.shields.io/badge/Falco-runtime--security-00ADEF?logo=falco&logoColor=white)](https://falco.org/)
[![Vault](https://img.shields.io/badge/Vault-1.15.4-FFCF25?logo=vault&logoColor=black)](https://www.vaultproject.io/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-20-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
[![Docker](https://img.shields.io/badge/Docker-compose-2496ED?logo=docker&logoColor=white)](https://docs.docker.com/compose/)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-1.28-326CE5?logo=kubernetes&logoColor=white)](https://kubernetes.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

A production-grade **DevSecOps platform** that enforces security policies at every layer of the software delivery lifecycle — from container image scanning in CI to runtime threat detection in production.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Kubernetes Cluster                     │
│                                                         │
│  ┌──────────────┐    ┌───────────────────────────────┐  │
│  │  Admission   │───▶│  policy-api (Node.js/TS)      │  │
│  │  Webhook     │    │  + OPA sidecar                │  │
│  └──────────────┘    └───────────────────────────────┘  │
│                                                         │
│  ┌──────────────────────────────────────────────────┐   │
│  │  compliance-reporter (Node.js/TS)                │   │
│  │  Reads OPA results + Trivy reports               │   │
│  └──────────────────────────────────────────────────┘   │
│                                                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐  │
│  │  Falco   │  │  Vault   │  │  NetworkPolicy / RBAC │  │
│  │ (runtime)│  │(secrets) │  │  ResourceQuota / PDB  │  │
│  └──────────┘  └──────────┘  └──────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                          ▲
          ┌───────────────┴──────────────────┐
          │           GitHub Actions CI       │
          │  typecheck → OPA tests → Trivy   │
          │  → kubeconform                   │
          └──────────────────────────────────┘
```

---

## Stack

| Component | Role |
|---|---|
| **Open Policy Agent (OPA)** | Policy-as-code engine. `.rego` policies enforce rules like "no container may run as root" and "all deployments must have resource limits." The `policy-api` queries OPA before allowing any Kubernetes resource through. |
| **Trivy** | Scans container images and IaC files (Dockerfiles, K8s manifests) for CVEs, misconfigurations, and exposed secrets. Runs in CI on every PR and fails the build if HIGH/CRITICAL vulns are found. |
| **Falco** | Runtime threat detection. Watches syscalls and K8s audit logs for suspicious behavior — container shell spawns, reads of `/etc/shadow`, unexpected network connections. Rules ship as YAML. |
| **HashiCorp Vault** | Secrets management. Services never read secrets from env vars or files — they authenticate via Kubernetes service account tokens and pull secrets dynamically at runtime. |
| **policy-api** | REST API that receives admission webhook requests and proxies them to OPA for a pass/fail decision. Returns structured JSON audit logs. |
| **compliance-reporter** | Reads OPA evaluation results and Trivy scan reports, generates a compliance summary (JSON + human-readable) broken down by severity and policy category. |

---

## Project Structure

```
security-compliance-platform/
├── .github/workflows/ci.yml        # CI: typecheck, OPA tests, Trivy, kubeconform
├── services/
│   ├── policy-api/                 # Admission webhook proxy (TypeScript/Node.js)
│   └── compliance-reporter/        # Compliance report generator (TypeScript/Node.js)
├── policies/
│   ├── kubernetes/                 # OPA .rego policies
│   └── tests/                      # OPA unit tests
├── falco/rules/                    # Custom Falco threat detection rules
├── vault/config/                   # Vault dev config
├── k8s/                            # Production Kubernetes manifests
├── docker-compose.yml              # Local development stack
└── README.md
```

---

## OPA Policies

Policies live in `policies/kubernetes/` and are enforced via the admission webhook:

| Policy | Description |
|---|---|
| `no_root_containers.rego` | Blocks pods/deployments where any container runs as root (`runAsNonRoot: false` or `runAsUser: 0`) |
| `require_resource_limits.rego` | Requires CPU and memory limits on every container |
| `require_labels.rego` | Requires `app`, `version`, and `team` labels on all workload resources |
| `no_privileged_containers.rego` | Blocks privileged containers and those with `allowPrivilegeEscalation: true` |

---

## CI Pipeline

Four jobs run on every push and pull request:

```
typecheck-build (matrix: policy-api, compliance-reporter)
    └── npm ci → tsc --noEmit → npm run build

opa-tests
    └── conftest test kubernetes/ --policy tests/

trivy-scan
    └── Dockerfiles + k8s/ manifests → fail on HIGH/CRITICAL

kubeconform
    └── Validate all k8s/ manifests against Kubernetes 1.28 schemas
```

---

## Kubernetes Manifests

| Manifest | Purpose |
|---|---|
| `namespace.yaml` | `security-platform` namespace with PodSecurity `restricted` profile enforced |
| `network-policy.yaml` | Default deny-all + selective allow for inter-service and DNS traffic |
| `pod-disruption-budget.yaml` | `minAvailable: 1` PDBs for both services during node drains |
| `rbac.yaml` | Service accounts, least-privilege roles, Vault auth ClusterRole |
| `resource-quota.yaml` | Namespace-level CPU/memory quotas + LimitRange defaults |
| `policy-api-deployment.yaml` | Deployment with OPA sidecar, Vault agent injection, read-only filesystem |
| `compliance-reporter-deployment.yaml` | Deployment with Vault agent injection, non-root, dropped capabilities |

---

## Local Development

### Prerequisites
- Docker + Docker Compose
- Node.js 20+

### Start the full stack

```bash
docker compose up --build
```

Services:
- `policy-api` → http://localhost:8080
- `compliance-reporter` → http://localhost:8090
- `OPA` → http://localhost:8181
- `Vault` → http://localhost:8200 (token: `root`)

### Test the admission webhook

```bash
curl -X POST http://localhost:8080/admission/validate \
  -H "Content-Type: application/json" \
  -d '{
    "apiVersion": "admission.k8s.io/v1",
    "kind": "AdmissionReview",
    "request": {
      "uid": "test-001",
      "kind": {"group": "", "version": "v1", "kind": "Pod"},
      "resource": {"group": "", "version": "v1", "resource": "pods"},
      "name": "test-pod",
      "namespace": "default",
      "operation": "CREATE",
      "object": {
        "metadata": {
          "name": "test-pod",
          "labels": {"app": "test", "version": "v1", "team": "platform"}
        },
        "spec": {
          "containers": [{
            "name": "app",
            "image": "nginx:latest",
            "securityContext": {"runAsNonRoot": true, "allowPrivilegeEscalation": false},
            "resources": {"limits": {"cpu": "100m", "memory": "128Mi"}}
          }]
        }
      },
      "userInfo": {"username": "admin", "uid": "admin-001", "groups": ["system:masters"]}
    }
  }'
```

### Generate a compliance report

```bash
curl -X POST http://localhost:8090/report \
  -H "Content-Type: application/json" \
  -d '{
    "trivyReport": {
      "SchemaVersion": 2,
      "ArtifactName": "policy-api:latest",
      "ArtifactType": "container_image",
      "Results": []
    },
    "opaResults": []
  }'
```

---

## Falco Rules

Custom rules in `falco/rules/custom_rules.yaml` detect:

- **Container shell spawn** — any shell (`bash`, `sh`, `zsh`, etc.) spawned inside a container
- **Sensitive file reads** — `/etc/shadow`, `/etc/sudoers`, SSH keys accessed from unexpected processes
- **Unexpected outbound connections** — egress to unapproved destinations
- **Binary directory writes** — writes to `/bin`, `/sbin`, `/usr/bin` inside containers
- **Kubernetes secret access** — secret reads/lists via K8s audit log from non-approved identities

---

## Vault Integration

Services authenticate to Vault using Kubernetes service account tokens (no static secrets):

```
Pod starts
  └── Vault agent sidecar reads K8s SA token
      └── Vault validates token against K8s TokenReview API
          └── Returns short-lived Vault token
              └── Service reads secrets from Vault KV store
```

Configure roles after starting the dev stack:

```bash
# Enable Kubernetes auth
vault auth enable kubernetes

# Configure role for policy-api
vault write auth/kubernetes/role/policy-api \
    bound_service_account_names=policy-api-sa \
    bound_service_account_namespaces=security-platform \
    policies=policy-api \
    ttl=1h
```

---

## GitHub About Section Topics

```
opa open-policy-agent policy-as-code trivy falco vault secrets-management
devsecops security compliance kubernetes docker typescript nodejs
github-actions platform-engineering sre admission-webhook runtime-security
vulnerability-scanning
```

---

## Author

[![GitHub](https://img.shields.io/badge/GitHub-Djones--qa-181717?logo=github&logoColor=white)](https://github.com/Djones-qa)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Darrius%20Jones-0A66C2?logo=linkedin&logoColor=white)](https://linkedin.com/in/darrius-jones-28226b350)

---

## License

This project is licensed under the [MIT License](./LICENSE).
