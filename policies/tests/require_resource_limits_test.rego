package kubernetes.admission_test

import future.keywords.if
import data.kubernetes.admission

# Test: deny pod missing CPU limit
test_deny_missing_cpu_limit if {
    result := admission.deny with input as {
        "kind": {"kind": "Pod"},
        "object": {
            "metadata": {"name": "test-pod", "labels": {"app": "test", "version": "v1", "team": "platform"}},
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx:latest",
                    "securityContext": {"runAsNonRoot": true},
                    "resources": {"limits": {"memory": "128Mi"}}
                }]
            }
        }
    }
    count(result) > 0
}

# Test: deny pod missing memory limit
test_deny_missing_memory_limit if {
    result := admission.deny with input as {
        "kind": {"kind": "Pod"},
        "object": {
            "metadata": {"name": "test-pod", "labels": {"app": "test", "version": "v1", "team": "platform"}},
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx:latest",
                    "securityContext": {"runAsNonRoot": true},
                    "resources": {"limits": {"cpu": "100m"}}
                }]
            }
        }
    }
    count(result) > 0
}

# Test: allow pod with both limits
test_allow_with_resource_limits if {
    result := admission.deny with input as {
        "kind": {"kind": "Pod"},
        "object": {
            "metadata": {"name": "test-pod", "labels": {"app": "test", "version": "v1", "team": "platform"}},
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx:latest",
                    "securityContext": {"runAsNonRoot": true, "allowPrivilegeEscalation": false},
                    "resources": {"limits": {"cpu": "100m", "memory": "128Mi"}}
                }]
            }
        }
    }
    count(result) == 0
}
