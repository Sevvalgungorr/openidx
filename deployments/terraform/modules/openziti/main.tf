# OpenZiti Fabric Module - Main Configuration
# Deploys the OpenZiti overlay control + data plane (Wave D3) via the openidx
# Helm chart's zitiFabric.* values. Disabled by default; enabling stands up the
# controller StatefulSet (HA/Raft when replicas >= 3), edge router, and Services.
#
# Wiring the app services to the overlay (ZITI_CTRL_URL, identity enrollment) is a
# separate operator step; see docs/OPENIDX_ZITI_ARCHITECTURE.md.

# ============================================================================
# OpenZiti fabric via Helm
# ============================================================================

resource "helm_release" "openziti_fabric" {
  count      = var.enabled ? 1 : 0
  name       = "openidx-ziti-fabric"
  repository = var.chart_repository
  chart      = "openidx"
  namespace  = var.namespace
  version    = var.chart_version

  set {
    name  = "zitiFabric.enabled"
    value = var.enabled
  }

  set {
    name  = "zitiFabric.controller.replicas"
    value = var.controller_replicas
  }

  set {
    name  = "zitiFabric.controller.image"
    value = var.controller_image
  }

  set {
    name  = "zitiFabric.controller.advertisedAddress"
    value = var.controller_advertised_address
  }

  set {
    name  = "zitiFabric.controller.persistence.size"
    value = var.controller_storage_size
  }

  set {
    name  = "zitiFabric.router.replicas"
    value = var.router_replicas
  }

  set {
    name  = "zitiFabric.router.image"
    value = var.router_image
  }

  set {
    name  = "zitiFabric.router.advertisedAddress"
    value = var.router_advertised_address
  }

  set {
    name  = "zitiFabric.router.browzer.enabled"
    value = var.browzer_enabled
  }
}
