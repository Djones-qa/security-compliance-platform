package kubernetes.admission

import future.keywords.if
import future.keywords.in

# Deny privileged containers
deny contains msg if {
    input.kind.kind == "Pod"
    container := input.object.spec.containers[_]
    container.securityContext.privileged == true
    msg := sprintf("container '%v' must not run in privileged mode", [container.name])
}

deny contains msg if {
    input.kind.kind == "Deployment"
    container := input.object.spec.template.spec.containers[_]
    container.securityContext.privileged == true
    msg := sprintf("container '%v' must not run in privileged mode", [container.name])
}

# Deny containers that allow privilege escalation
deny contains msg if {
    input.kind.kind == "Pod"
    container := input.object.spec.containers[_]
    container.securityContext.allowPrivilegeEscalation == true
    msg := sprintf("container '%v' must not allow privilege escalation", [container.name])
}

deny contains msg if {
    input.kind.kind == "Deployment"
    container := input.object.spec.template.spec.containers[_]
    container.securityContext.allowPrivilegeEscalation == true
    msg := sprintf("container '%v' must not allow privilege escalation", [container.name])
}
