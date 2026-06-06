package kubernetes.admission_test

import data.kubernetes.admission

# Test: deny pod running as root via runAsNonRoot: false
test_deny_root_container_non_root_false if {
    result := admission.deny with input as {
        "kind": {"kind": "Pod"},
        "object": {
            "metadata": {"name": "test-pod", "labels": {"app": "test", "version": "v1", "team": "platform"}},
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx:latest",
                    "securityContext": {"runAsNonRoot": false},
                    "resources": {"limits": {"cpu": "100m", "memory": "128Mi"}}
                }]
            }
        }
    }
    count(result) > 0
}

# Test: allow pod with runAsNonRoot: true
test_allow_non_root_container if {
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

# Test: deny pod running as UID 0
test_deny_root_uid_zero if {
    result := admission.deny with input as {
        "kind": {"kind": "Pod"},
        "object": {
            "metadata": {"name": "test-pod", "labels": {"app": "test", "version": "v1", "team": "platform"}},
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx:latest",
                    "securityContext": {"runAsUser": 0},
                    "resources": {"limits": {"cpu": "100m", "memory": "128Mi"}}
                }]
            }
        }
    }
    count(result) > 0
}
