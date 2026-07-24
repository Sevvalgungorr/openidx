# OpenZiti Fabric Module - Variables

variable "enabled" {
  description = "Enable the OpenZiti fabric (controller + router)."
  type        = bool
  default     = false
}

variable "namespace" {
  description = "Kubernetes namespace to deploy the fabric into."
  type        = string
  default     = "openidx"
}

variable "chart_repository" {
  description = "Helm repository hosting the openidx chart."
  type        = string
  default     = "oci://ghcr.io/openidx/helm"
}

variable "chart_version" {
  description = "openidx Helm chart version."
  type        = string
  default     = "1.0.0"
}

variable "controller_replicas" {
  description = "Ziti controller replicas. Use an odd number >= 3 for a Raft HA quorum."
  type        = number
  default     = 1

  validation {
    condition     = var.controller_replicas >= 1 && var.controller_replicas <= 7
    error_message = "Controller replicas must be between 1 and 7 (use an odd number for Raft HA)."
  }
}

variable "controller_image" {
  description = "Ziti controller container image."
  type        = string
  default     = "openziti/ziti-controller:latest"
}

variable "controller_advertised_address" {
  description = "FQDN the controller advertises to routers and clients (must resolve + be in the server cert SAN)."
  type        = string
  default     = "ziti-controller"
}

variable "controller_storage_size" {
  description = "PVC size for controller bbolt + Raft data (per replica)."
  type        = string
  default     = "5Gi"
}

variable "router_replicas" {
  description = "Edge router replicas (data plane)."
  type        = number
  default     = 1

  validation {
    condition     = var.router_replicas >= 1 && var.router_replicas <= 20
    error_message = "Router replicas must be between 1 and 20."
  }
}

variable "router_image" {
  description = "Ziti edge router container image."
  type        = string
  default     = "openziti/ziti-router:latest"
}

variable "router_advertised_address" {
  description = "FQDN the edge router advertises (data plane; must resolve from clients)."
  type        = string
  default     = "ziti-router"
}

variable "browzer_enabled" {
  description = "Expose the router's BrowZer WSS port (3023) for browser zero-trust access."
  type        = bool
  default     = false
}
