# OpenIDX on Azure — AKS + managed Postgres + managed Redis.
#
# Mirrors the AWS stack (EKS + RDS + ElastiCache) so the platform's availability
# story is the same on both clouds. Kept in its own directory rather than added
# to the AWS root: the two would otherwise share a state file and a provider
# block, and `terraform apply` for one cloud would plan changes for the other.
#
# What makes this "always-on" rather than merely "deployed":
#   - the node pool spans availability zones, so losing one zone does not take
#     the cluster with it;
#   - Postgres is zone-redundant with automatic failover in prod;
#   - Redis is replicated, because the session store dying logs everybody out.
#
# The Helm chart's own HA settings (replicas, PDBs, topology spread, graceful
# termination) are what make the workloads survive; this file makes sure the
# infrastructure underneath can survive too. One without the other is not HA.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.25"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.12"
    }
  }

  # State lives in Azure Storage with native blob leasing, which gives the same
  # locking guarantee DynamoDB provides on AWS. Two concurrent applies against
  # one environment is how infrastructure gets corrupted.
  backend "azurerm" {
    resource_group_name  = "openidx-tfstate"
    storage_account_name = "openidxtfstate"
    container_name       = "tfstate"
    key                  = "infrastructure.tfstate"
  }
}

provider "azurerm" {
  features {
    resource_group {
      # Refuse to delete a resource group that still contains resources. The
      # default silently takes everything with it.
      prevent_deletion_if_contains_resources = true
    }
  }
}

locals {
  # Zones are the unit of failure this design plans around. Three is the
  # smallest number that survives one loss while keeping a quorum for
  # quorum-based components (the Ziti controller's Raft group, for example).
  zones = ["1", "2", "3"]

  common_tags = {
    Project     = "OpenIDX"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

resource "azurerm_resource_group" "this" {
  name     = "openidx-${var.environment}"
  location = var.location
  tags     = local.common_tags
}

# ---------------------------------------------------------------- networking
resource "azurerm_virtual_network" "this" {
  name                = "openidx-vnet-${var.environment}"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.common_tags
}

resource "azurerm_subnet" "aks" {
  name                 = "aks"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = ["10.0.1.0/24"]
}

# Postgres Flexible Server requires its own delegated subnet for private access.
# Keeping the database off the public internet is not optional for an identity
# platform.
resource "azurerm_subnet" "database" {
  name                 = "database"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = ["10.0.2.0/24"]
  service_endpoints    = ["Microsoft.Storage"]

  delegation {
    name = "postgres"
    service_delegation {
      name = "Microsoft.DBforPostgreSQL/flexibleServers"
      actions = [
        "Microsoft.Network/virtualNetworks/subnets/join/action",
      ]
    }
  }
}

resource "azurerm_private_dns_zone" "postgres" {
  name                = "openidx-${var.environment}.postgres.database.azure.com"
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.common_tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "postgres" {
  name                  = "openidx-${var.environment}"
  private_dns_zone_name = azurerm_private_dns_zone.postgres.name
  virtual_network_id    = azurerm_virtual_network.this.id
  resource_group_name   = azurerm_resource_group.this.name
}

# --------------------------------------------------------------------- AKS
resource "azurerm_kubernetes_cluster" "this" {
  name                = var.cluster_name
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  dns_prefix          = var.cluster_name
  kubernetes_version  = var.kubernetes_version
  tags                = local.common_tags

  default_node_pool {
    name    = "system"
    vm_size = var.environment == "prod" ? "Standard_D4s_v5" : "Standard_D2s_v5"

    # Spreading nodes across zones is what makes the chart's
    # topologySpreadConstraints mean anything: a zone spread cannot help if
    # every node is in one zone.
    zones = local.zones

    auto_scaling_enabled = true
    min_count            = var.environment == "prod" ? 3 : 2
    max_count            = var.environment == "prod" ? 10 : 4

    vnet_subnet_id = azurerm_subnet.aks.id

    upgrade_settings {
      # Add a node before draining one during upgrades, so cluster capacity
      # never dips — the node-level counterpart of the chart's maxSurge.
      max_surge = "1"
    }
  }

  identity {
    type = "SystemAssigned"
  }

  network_profile {
    network_plugin = "azure"
    network_policy = "calico"
    # Standard is required for zone-redundant load balancing; Basic is
    # single-zone and would undo the node spread above.
    load_balancer_sku = "standard"
  }

  # Workload identity lets pods authenticate to Azure services without a stored
  # credential, the same reason IRSA is enabled on the AWS side.
  oidc_issuer_enabled       = true
  workload_identity_enabled = true
}

# ------------------------------------------------------------------ Postgres
resource "azurerm_postgresql_flexible_server" "this" {
  name                = "openidx-${var.environment}"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  version             = "16"
  tags                = local.common_tags

  delegated_subnet_id           = azurerm_subnet.database.id
  private_dns_zone_id           = azurerm_private_dns_zone.postgres.id
  public_network_access_enabled = false

  administrator_login    = var.db_admin_username
  administrator_password = var.db_admin_password

  sku_name   = var.environment == "prod" ? "GP_Standard_D4s_v3" : "B_Standard_B2s"
  storage_mb = var.environment == "prod" ? 262144 : 32768

  # Zone-redundant HA keeps a synchronous standby in a different zone and fails
  # over automatically. Only in prod: it doubles the cost, and a dev outage is
  # an inconvenience rather than an incident.
  dynamic "high_availability" {
    for_each = var.environment == "prod" ? [1] : []
    content {
      mode                      = "ZoneRedundant"
      standby_availability_zone = "2"
    }
  }

  # Backups are the last line of defence: HA covers a failed instance, not a
  # bad migration or a deleted table.
  backup_retention_days        = var.environment == "prod" ? 35 : 7
  geo_redundant_backup_enabled = var.environment == "prod"

  lifecycle {
    # Losing the identity platform's database is unrecoverable; make an
    # accidental destroy impossible rather than merely unlikely.
    prevent_destroy = true
  }

  depends_on = [azurerm_private_dns_zone_virtual_network_link.postgres]
}

# --------------------------------------------------------------------- Redis
# Sessions live here. A Redis restart without replication logs every user out,
# so this is an availability component, not just a cache.
resource "azurerm_redis_cache" "this" {
  name                = "openidx-${var.environment}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.common_tags

  # Premium is what buys zone redundancy and replication; Standard is a single
  # zone and Basic has no replica at all.
  sku_name = var.environment == "prod" ? "Premium" : "Standard"
  family   = var.environment == "prod" ? "P" : "C"
  capacity = var.environment == "prod" ? 1 : 1

  # Zone redundancy is only available on Premium.
  zones = var.environment == "prod" ? local.zones : null

  non_ssl_port_enabled = false
  minimum_tls_version  = "1.2"
}

# --------------------------------------------------------------- Key Vault
# The Helm chart reads secrets through ExternalSecrets rather than holding them
# in values; this is the store it reads from.
resource "azurerm_key_vault" "this" {
  name                       = "openidx-${var.environment}-kv"
  location                   = azurerm_resource_group.this.location
  resource_group_name        = azurerm_resource_group.this.name
  tenant_id                  = var.tenant_id
  sku_name                   = "standard"
  purge_protection_enabled   = var.environment == "prod"
  soft_delete_retention_days = 7
  tags                       = local.common_tags
}
