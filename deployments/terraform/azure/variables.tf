variable "environment" {
  description = "Deployment environment. Drives the cost/availability trade-offs: prod gets zone-redundant Postgres, a replicated Redis and a larger node floor."
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "location" {
  description = "Azure region. Must be one that offers availability zones, otherwise the zone spread this design relies on silently degrades to a single failure domain."
  type        = string
  default     = "westeurope"
}

variable "cluster_name" {
  description = "AKS cluster name."
  type        = string
  default     = "openidx"
}

variable "kubernetes_version" {
  description = "AKS control plane version. Pinned rather than latest so an upgrade is a deliberate, reviewable change."
  type        = string
  default     = "1.30"
}

variable "tenant_id" {
  description = "Azure AD tenant id that owns the Key Vault."
  type        = string
}

variable "db_admin_username" {
  description = "Postgres administrator login."
  type        = string
  default     = "openidx"
}

variable "db_admin_password" {
  description = "Postgres administrator password. Supply through a secret manager or TF_VAR_db_admin_password, never a committed tfvars file."
  type        = string
  sensitive   = true
}
