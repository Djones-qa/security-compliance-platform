package kubernetes.admission

import future.keywords.if
import future.keywords.in

# Deny if containers are missing CPU/memory limits
deny contains msg if {
    input.kind.kind == "Pod"
    container := input.object.spec.containers[_]
    not container.resources.limits.cpu
    msg := sprintf("container '%v' must have CPU limit set", [container.name])
}

deny contains msg if {
    input.kind.kind == "Pod"
    container := input.object.spec.containers[_]
    not container.resources.limits.memory
    msg := sprintf("container '%v' must have memory limit set", [container.name])
}

deny contains msg if {
    input.kind.kind == "Deployment"
    container := input.object.spec.template.spec.containers[_]
    not container.resources.limits.cpu
    msg := sprintf("container '%v' must have CPU limit set", [container.name])
}

deny contains msg if {
    input.kind.kind == "Deployment"
    container := input.object.spec.template.spec.containers[_]
    not container.resources.limits.memory
    msg := sprintf("container '%v' must have memory limit set", [container.name])
}
