output "resource_group_name" {
  description = "Resource group holding the whole stack."
  value       = azurerm_resource_group.this.name
}

output "cluster_name" {
  description = "AKS cluster name, for `az aks get-credentials`."
  value       = azurerm_kubernetes_cluster.this.name
}

output "cluster_oidc_issuer_url" {
  description = "OIDC issuer of the cluster, needed to bind workload identities."
  value       = azurerm_kubernetes_cluster.this.oidc_issuer_url
}

output "postgres_fqdn" {
  description = "Private FQDN of the Postgres server. Reachable only from inside the VNet by design."
  value       = azurerm_postgresql_flexible_server.this.fqdn
}

output "postgres_ha_enabled" {
  description = "Whether Postgres runs with a zone-redundant standby and automatic failover. False means a server failure is an outage until it is restored."
  value       = length(azurerm_postgresql_flexible_server.this.high_availability) > 0
}

output "redis_hostname" {
  description = "Redis hostname for the session store."
  value       = azurerm_redis_cache.this.hostname
}

output "redis_zone_redundant" {
  description = "Whether Redis spans availability zones. False means a zone outage drops every session."
  value       = azurerm_redis_cache.this.zones != null
}

output "key_vault_uri" {
  description = "Key Vault URI that ExternalSecrets reads from."
  value       = azurerm_key_vault.this.vault_uri
}
