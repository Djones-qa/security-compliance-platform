package kubernetes.admission_test

import future.keywords.if
import data.kubernetes.admission

# Test: deny privileged container
test_deny_privileged_container if {
    result := admission.deny with input as {
        "kind": {"kind": "Pod"},
        "object": {
            "metadata": {"name": "test-pod", "labels": {"app": "test", "version": "v1", "team": "platform"}},
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx:latest",
                    "securityContext": {"privileged": true, "runAsNonRoot": true},
                    "resources": {"limits": {"cpu": "100m", "memory": "128Mi"}}
                }]
            }
        }
    }
    count(result) > 0
}

# Test: deny privilege escalation
test_deny_privilege_escalation if {
    result := admission.deny with input as {
        "kind": {"kind": "Pod"},
        "object": {
            "metadata": {"name": "test-pod", "labels": {"app": "test", "version": "v1", "team": "platform"}},
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx:latest",
                    "securityContext": {"allowPrivilegeEscalation": true, "runAsNonRoot": true},
                    "resources": {"limits": {"cpu": "100m", "memory": "128Mi"}}
                }]
            }
        }
    }
    count(result) > 0
}

# Test: allow non-privileged container
test_allow_non_privileged if {
    result := admission.deny with input as {
        "kind": {"kind": "Pod"},
        "object": {
            "metadata": {"name": "test-pod", "labels": {"app": "test", "version": "v1", "team": "platform"}},
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx:latest",
                    "securityContext": {
                        "privileged": false,
                        "allowPrivilegeEscalation": false,
                        "runAsNonRoot": true
                    },
                    "resources": {"limits": {"cpu": "100m", "memory": "128Mi"}}
                }]
            }
        }
    }
    count(result) == 0
}
