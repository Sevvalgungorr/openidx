# OpenIDX Infrastructure - Terraform Configuration

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
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

  backend "s3" {
    bucket         = "openidx-terraform-state"
    key            = "infrastructure/terraform.tfstate"
    region         = "eu-west-1"
    encrypt        = true
    dynamodb_table = "openidx-terraform-locks"
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "OpenIDX"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# Variables
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "eu-west-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "dev"
}

variable "cluster_name" {
  description = "EKS cluster name"
  type        = string
  default     = "openidx-cluster"
}

variable "openziti_enabled" {
  description = "Deploy the OpenZiti fabric (controller + router) via the openidx Helm chart (Wave D3)."
  type        = bool
  default     = false
}

# VPC
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "openidx-vpc-${var.environment}"
  cidr = "10.0.0.0/16"

  azs             = ["${var.aws_region}a", "${var.aws_region}b", "${var.aws_region}c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

  enable_nat_gateway   = true
  single_nat_gateway   = var.environment == "dev"
  enable_dns_hostnames = true
  enable_dns_support   = true

  public_subnet_tags = {
    "kubernetes.io/role/elb" = 1
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1
  }
}

# EKS Cluster
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 19.0"

  cluster_name    = var.cluster_name
  cluster_version = "1.29"

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  cluster_endpoint_public_access = true

  eks_managed_node_groups = {
    default = {
      min_size     = 2
      max_size     = 10
      desired_size = 3

      instance_types = ["t3.large"]
      capacity_type  = "ON_DEMAND"
    }
  }

  # Enable IRSA
  enable_irsa = true
}

# RDS PostgreSQL
module "rds" {
  source = "./modules/rds"

  identifier     = "openidx-${var.environment}"
  engine_version = "16.1"
  instance_class = var.environment == "prod" ? "db.r6g.large" : "db.t3.medium"
  # Multi-AZ (synchronous standby + automatic failover) in prod; single-AZ in
  # dev to save cost. Mirrors the instance_class / NAT-gateway env conditionals.
  multi_az = var.environment == "prod"

  # One read replica in prod for the app's DATABASE_READ_URL (read-mostly,
  # lag-tolerant queries via PostgresDB.Reader) + a warm standby. None in dev.
  read_replica_count = var.environment == "prod" ? 1 : 0

  vpc_id          = module.vpc.vpc_id
  subnet_ids      = module.vpc.private_subnets
  security_groups = [module.eks.cluster_security_group_id]
}

# ElastiCache Redis
module "redis" {
  source = "./modules/elasticache"

  cluster_id      = "openidx-${var.environment}"
  node_type       = var.environment == "prod" ? "cache.r6g.large" : "cache.t3.medium"
  num_cache_nodes = var.environment == "prod" ? 3 : 1

  vpc_id          = module.vpc.vpc_id
  subnet_ids      = module.vpc.private_subnets
  security_groups = [module.eks.cluster_security_group_id]
}

# OpenZiti fabric (Wave D3). Disabled by default; set openziti_enabled=true and
# controller_replicas=3 for a Raft HA quorum. Renders through the openidx Helm
# chart's zitiFabric.* values.
module "openziti" {
  source = "./modules/openziti"

  enabled             = var.openziti_enabled
  namespace           = "openidx"
  controller_replicas = var.environment == "prod" ? 3 : 1
  router_replicas     = var.environment == "prod" ? 2 : 1
}

# Outputs
output "cluster_endpoint" {
  description = "EKS cluster endpoint"
  value       = module.eks.cluster_endpoint
}

output "cluster_name" {
  description = "EKS cluster name"
  value       = module.eks.cluster_name
}

output "rds_endpoint" {
  description = "RDS endpoint"
  value       = module.rds.endpoint
}

output "rds_reader_endpoints" {
  description = "RDS read-replica endpoints (empty in dev). Build DATABASE_READ_URL from one of these to enable the app read pool."
  value       = module.rds.reader_endpoints
}

output "redis_endpoint" {
  description = "Redis endpoint"
  value       = module.redis.endpoint
}

output "openziti_ha_enabled" {
  description = "True when the OpenZiti controller runs a Raft HA quorum (replicas >= 3)."
  value       = module.openziti.ha_enabled
}
