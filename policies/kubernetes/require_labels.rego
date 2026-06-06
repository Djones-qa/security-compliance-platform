package kubernetes.admission

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Required labels for all workloads
required_labels := {"app", "version", "team"}

deny contains msg if {
    _is_workload(input.kind.kind)
    required_label := required_labels[_]
    not input.object.metadata.labels[required_label]
    msg := sprintf("resource '%v' is missing required label '%v'", [input.object.metadata.name, required_label])
}

_is_workload(kind) if kind == "Pod"
_is_workload(kind) if kind == "Deployment"
_is_workload(kind) if kind == "StatefulSet"
_is_workload(kind) if kind == "DaemonSet"
