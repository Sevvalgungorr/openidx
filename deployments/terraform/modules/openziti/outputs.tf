# OpenZiti Fabric Module - Outputs

output "enabled" {
  description = "Whether the OpenZiti fabric is enabled."
  value       = var.enabled
}

output "controller_replicas" {
  description = "Number of Ziti controller replicas (>= 3 = Raft HA)."
  value       = var.controller_replicas
}

output "ha_enabled" {
  description = "True when the controller runs a Raft quorum (replicas >= 3)."
  value       = var.controller_replicas >= 3
}

output "controller_advertised_address" {
  description = "FQDN the controller advertises."
  value       = var.controller_advertised_address
}

output "router_advertised_address" {
  description = "FQDN the edge router advertises."
  value       = var.router_advertised_address
}

output "release_name" {
  description = "Helm release name for the fabric (empty when disabled)."
  value       = var.enabled ? helm_release.openziti_fabric[0].name : ""
}
