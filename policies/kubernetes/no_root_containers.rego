package kubernetes.admission

import future.keywords.if
import future.keywords.in

default allow = false

# Allow if no deny reasons
allow if {
    count(deny) == 0
}

# Deny if any container runs as root
deny contains msg if {
    input.kind.kind == "Pod"
    container := input.object.spec.containers[_]
    _runs_as_root(container)
    msg := sprintf("container '%v' must not run as root (set securityContext.runAsNonRoot: true)", [container.name])
}

deny contains msg if {
    input.kind.kind == "Deployment"
    container := input.object.spec.template.spec.containers[_]
    _runs_as_root(container)
    msg := sprintf("container '%v' must not run as root (set securityContext.runAsNonRoot: true)", [container.name])
}

_runs_as_root(container) if {
    container.securityContext.runAsNonRoot == false
}

_runs_as_root(container) if {
    container.securityContext.runAsUser == 0
}

_runs_as_root(container) if {
    not container.securityContext.runAsNonRoot
    not container.securityContext.runAsUser
}
