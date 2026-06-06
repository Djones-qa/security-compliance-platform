package kubernetes.admission_test

import data.kubernetes.admission

# Test: deny pod missing required labels
test_deny_missing_labels if {
    result := admission.deny with input as {
        "kind": {"kind": "Pod"},
        "object": {
            "metadata": {"name": "test-pod", "labels": {"app": "test"}},
            "spec": {
                "containers": [{
                    "name": "app",
                    "securityContext": {"runAsNonRoot": true},
                    "resources": {"limits": {"cpu": "100m", "memory": "128Mi"}}
                }]
            }
        }
    }
    count(result) > 0
}

# Test: allow pod with all required labels
test_allow_all_labels if {
    result := admission.deny with input as {
        "kind": {"kind": "Pod"},
        "object": {
            "metadata": {"name": "test-pod", "labels": {"app": "test", "version": "v1", "team": "platform"}},
            "spec": {
                "containers": [{
                    "name": "app",
                    "securityContext": {"runAsNonRoot": true, "allowPrivilegeEscalation": false},
                    "resources": {"limits": {"cpu": "100m", "memory": "128Mi"}}
                }]
            }
        }
    }
    count(result) == 0
}
