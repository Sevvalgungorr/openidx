# OpenIDX Makefile
# Build, test, and deploy automation

.PHONY: all build test lint clean dev dev-infra docker helm docs smoke-test ha-drill k8s-chaos dr-game-day dark-drill dark-drill-live build-agent build-agent-all test-agent docker-build-agent ziti-quickstart ziti-down

# Variables
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
COMMIT_HASH := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.CommitHash=$(COMMIT_HASH)"

# Go parameters
GOCMD := go
GOBUILD := $(GOCMD) build $(LDFLAGS)
GOTEST := $(GOCMD) test
GOMOD := $(GOCMD) mod
GOLINT := golangci-lint

# Docker parameters
DOCKER := docker
DOCKER_COMPOSE := docker-compose
DOCKER_REGISTRY ?= ghcr.io/openidx

# Kubernetes parameters
KUBECTL := kubectl
HELM := helm
NAMESPACE ?= openidx

# Services
SERVICES := identity-service governance-service provisioning-service audit-service gateway-service admin-api oauth-service access-service

# Tools
TOOLS := profiler migrate openidx

#---------------------------------------------------------------------------
# Default target
#---------------------------------------------------------------------------

all: deps lint test build

#---------------------------------------------------------------------------
# Dependencies
#---------------------------------------------------------------------------

deps:
	@echo "📦 Installing dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy
	cd web/admin-console && npm install

deps-tools:
	@echo "🔧 Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/swaggo/swag/cmd/swag@latest
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

#---------------------------------------------------------------------------
# Build
#---------------------------------------------------------------------------

build: build-services build-tools build-web build-cli

build-services:
	@echo "🔨 Building services..."
	@for service in $(SERVICES); do \
		echo "  Building $$service..."; \
		$(GOBUILD) -o bin/$$service ./cmd/$$service; \
	done

build-tools:
	@echo "🔧 Building tools..."
	@for tool in $(TOOLS); do \
		if [ -d "./cmd/$$tool" ]; then \
			echo "  Building $$tool..."; \
			$(GOBUILD) -o bin/$$tool ./cmd/$$tool; \
		fi \
	done

build-web:
	@echo "🌐 Building web applications..."
	cd web/admin-console && npm run build

build-linux:
	@echo "🐧 Building for Linux..."
	@for service in $(SERVICES); do \
		GOOS=linux GOARCH=amd64 $(GOBUILD) -o bin/linux/$$service ./cmd/$$service; \
	done
	@for tool in $(TOOLS); do \
		if [ -d "./cmd/$$tool" ]; then \
			GOOS=linux GOARCH=amd64 $(GOBUILD) -o bin/linux/$$tool ./cmd/$$tool; \
		fi \
	done

#---------------------------------------------------------------------------
# Testing
#---------------------------------------------------------------------------

test:
	@echo "🧪 Running tests..."
	$(GOTEST) -v -race -cover ./...

test-coverage:
	@echo "📊 Running tests with coverage..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

test-integration:
	@echo "🔗 Running integration tests..."
	$(GOTEST) -v -tags=integration ./test/integration/...

test-e2e:
	@echo "🎭 Running end-to-end tests..."
	cd web/admin-console && npx playwright test

smoke-test:
	@echo "Running smoke tests..."
	@./scripts/smoke-test.sh

#---------------------------------------------------------------------------
# Availability drill — verify the "always-available auth" guarantees
#---------------------------------------------------------------------------
# Runs the focused Go tests that encode each availability tier (see
# docs/architecture/always-available-auth-plan.md). This is the single command
# to prove the guarantees hold; each maps to a tier and fails loudly if a change
# regresses it. Data-tier failover itself is exercised by the DR game-day
# (docs/disaster-recovery.md §1D) against a live DB, not here.
ha-drill:
	@echo "🛡️  OpenIDX availability drill — verifying always-available-auth guarantees"
	@echo ""
	@bash scripts/ha-drill.sh "Tier 0: verify path survives a JWKS/DB outage (serve-stale)" \
		./internal/common/middleware/ \
		'ServeStaleJWKSOnRefreshFailure|StaleJWKSExpiresAfterMaxStale|NoStaleServeWithoutSuccessfulFetch|AuthMiddlewareSurvivesIssuerOutage'
	@bash scripts/ha-drill.sh "Tier 1: bounded DB timeouts" \
		./internal/common/database/ \
		'BuildPoolConfigConnectTimeoutDefault|BuildPoolConfigStatementTimeout|ReaderFallsBackToPrimary|PingReadNoReplicaIsNil'
	@bash scripts/ha-drill.sh "Tier 1: read-replica health checker (non-critical)" \
		./internal/health/ 'ReadReplicaCheckerNonCritical'
	@bash scripts/ha-drill.sh "Tier 2: issue-path brownout + Redis breaker" \
		./internal/oauth/ \
		'IsDependencyUnavailable|WriteServerOrUnavailable|RevocationBreakerFastFailsOnRedisOutage'
	@bash scripts/ha-drill.sh "Guards: identity read/write pool safety (mutation-tested)" \
		./internal/identity/ \
		'WritesNeverUseReplica|ReadsUseReplica|SecurityCriticalReadUsesPrimary'
	@bash scripts/ha-drill.sh "Guards: oauth client store pool safety (mutation-tested)" \
		./internal/oauth/ \
		'OAuthClientStoreWritesUsePrimary|OAuthClientGetUsesPrimary'
	@bash scripts/ha-drill.sh "Guards: admin settings store pool safety (mutation-tested)" \
		./internal/admin/ \
		'SettingsRepositoryWritesUsePrimary|SettingsRepositoryGetUsesPrimary'
	@echo "✅ Availability drill passed — all always-available-auth guarantees hold."

#---------------------------------------------------------------------------
# DR game-day — rehearse data-tier failover (docs/disaster-recovery.md §1D).
# `dr-game-day` runs the self-test: it stands up a local mock that simulates a
# failover window and drives the whole canary/verdict logic against it, so the
# drill itself is verified (a false-green DR drill is worse than none) with NO
# infrastructure. To run against real staging, call the script directly:
#   scripts/dr-game-day.sh --base-url https://staging.openidx.example --trigger \
#       --provider rds --rds-instance openidx-staging
dr-game-day:
	@bash scripts/dr-game-day.sh --self-test

#---------------------------------------------------------------------------
# Dark-mode drill — verify the "dark platform" posture (docs/superpowers/specs/
# 2026-07-17-dark-platform-ziti-first-design.md). Runs the dark-mode.sh self-test
# (mock public + overlay, no infra) proving the two-sided invariant logic —
# public refused / overlay reachable / tier gate holds — so a cutover can't be
# green-lit on a false positive. Also runs the edge route-set assertions.
# For a live check: scripts/dark-mode.sh --verify --public-url ... --overlay-url ...
# Kubernetes always-on drill. `--static` inspects the rendered chart and needs
# no cluster, so it can run in CI: it fails if any Deployment would ship without
# graceful termination, zone spread, a capacity-preserving rollout or a PDB.
# For real evidence run it against a cluster:
#   scripts/k8s-chaos-drill.sh --namespace openidx --url https://api.example.com
# which kills pods, restarts rollouts and drains nodes under continuous polling
# and reports the requests actually lost.
k8s-chaos:
	@bash scripts/k8s-chaos-drill.sh --static

dark-drill:
	@bash deployments/apisix-edge/seed-edge-routes.test.sh
	@bash scripts/register-console-dark-app.test.sh
	@go test ./internal/access/ -run 'TestTier2ServicesRequireDeviceTrust|TestNoTier0SurfaceIsDarked|TestDarkServiceUpstreamsAreLoopback|TestDarkServiceNamesAreUnique|TestDefaultDarkServicesTiers|TestReconcileDarkServicesCreatesServiceAndTierPolicy' -count=1
	@bash scripts/dark-mode.sh --self-test

# Opt-in LIVE drill against the running edge (needs APISIX_ADMIN_KEY + a live
# oidx-apisix). Self-restoring: darks the tier, measures per-service effect, then
# reverts to the exact prior route set. DARK_TIER=tier1 to also dark self-service
# + SPA (only the Tier-0 bootstrap stays public). NOT part of `dark-drill` — it
# touches the live edge, so run it deliberately:
#   APISIX_ADMIN_KEY=... make dark-drill-live            # tier2
#   APISIX_ADMIN_KEY=... DARK_TIER=tier1 make dark-drill-live
dark-drill-live:
	@bash scripts/dark-drill-live.sh $(or $(DARK_TIER),tier2)

#---------------------------------------------------------------------------
# Linting
#---------------------------------------------------------------------------

lint:
	@echo "🔍 Running linters..."
	$(GOLINT) run ./...

lint-fix:
	@echo "🔧 Fixing lint issues..."
	$(GOLINT) run --fix ./...

lint-web:
	@echo "🔍 Linting web applications..."
	cd web/admin-console && npm run lint

#---------------------------------------------------------------------------
# Development
#---------------------------------------------------------------------------

dev-infra:
	@echo "🏗️  Starting infrastructure services..."
	$(DOCKER_COMPOSE) -f deployments/docker/docker-compose.infra.yml up -d
	@echo "Waiting for services to be ready..."
	@sleep 10
	@echo "✅ Infrastructure ready!"

dev:
	@echo "🚀 Starting development environment..."
	$(DOCKER_COMPOSE) -f deployments/docker/docker-compose.yml up -d
	@echo "✅ Services running at:"
	@echo "   - Admin Console: http://localhost:3000"
	@echo "   - API Gateway:   http://localhost:8080"
	@echo "   - Keycloak:      http://localhost:8180"

dev-stop:
	@echo "🛑 Stopping development environment..."
	$(DOCKER_COMPOSE) -f deployments/docker/docker-compose.yml down

dev-logs:
	$(DOCKER_COMPOSE) -f deployments/docker/docker-compose.yml logs -f

dev-clean:
	@echo "🧹 Cleaning development environment..."
	$(DOCKER_COMPOSE) -f deployments/docker/docker-compose.yml down -v --remove-orphans

# HA=1 adds a second edge router (redundant data plane): make ziti-quickstart HA=1
ziti-quickstart:
	@HA=$(HA) ./scripts/ziti-quickstart.sh

ziti-down:
	@HA=$(HA) ./scripts/ziti-quickstart.sh down

#---------------------------------------------------------------------------
# Profiling
#---------------------------------------------------------------------------

build-profiler:
	@echo "🔬 Building profiler..."
	$(GOBUILD) -o bin/profiler ./cmd/profiler

profiler-cpu:
	@echo "Capturing CPU profile..."
	@if [ -z "$(SERVICE)" ]; then \
		echo "Error: SERVICE variable required. Usage: make profiler-cpu SERVICE=identity-service DURATION=30s"; \
		exit 1; \
	fi
	./bin/profiler cpu $(SERVICE) $(DURATION)

profiler-mem:
	@echo "Capturing memory profile..."
	@if [ -z "$(SERVICE)" ]; then \
		echo "Error: SERVICE variable required. Usage: make profiler-mem SERVICE=identity-service"; \
		exit 1; \
	fi
	./bin/profiler mem $(SERVICE)

profiler-trace:
	@echo "Capturing execution trace..."
	@if [ -z "$(SERVICE)" ]; then \
		echo "Error: SERVICE variable required. Usage: make profiler-trace SERVICE=identity-service DURATION=5s"; \
		exit 1; \
	fi
	./bin/profiler trace $(SERVICE) $(DURATION)

profiler-flame:
	@echo "Generating flame graph..."
	@if [ -z "$(PROFILE)" ]; then \
		echo "Error: PROFILE variable required. Usage: make profiler-flame PROFILE=cpu.prof"; \
		exit 1; \
	fi
	@if ! command -v flamegraph.pl >/dev/null 2>&1; then \
		echo "Error: flamegraph.pl not found. Install from: https://github.com/brendangregg/FlameGraph"; \
		exit 1; \
	fi
	flamegraph.pl --title "$(SERVICE) CPU Flame Graph" $(PROFILE) > $(SERVICE)-flamegraph.svg
	@echo "Flame graph generated: $(SERVICE)-flamegraph.svg"

#---------------------------------------------------------------------------
# CLI Tool
#---------------------------------------------------------------------------

build-cli:
	@echo "🛠️  Building OpenIDX CLI..."
	@$(GOBUILD) -o bin/openidx ./cmd/openidx
	@echo "✅ CLI built: bin/openidx"

build-agent:
	@echo "Building openidx-agent..."
	cd agent && go build -o ../bin/openidx-agent ./cmd/openidx-agent

build-agent-all:
	@echo "Cross-compiling openidx-agent..."
	cd agent && make build-all
	cp agent/bin/* bin/ 2>/dev/null || true

test-agent:
	@echo "Testing openidx-agent..."
	cd agent && go test -v -race ./...

install-cli: build-cli
	@echo "📦 Installing OpenIDX CLI..."
	@cp bin/openidx $(GOPATH)/bin/openidx || sudo cp bin/openidx /usr/local/bin/openidx
	@echo "✅ CLI installed"

cli-install-completion:
	@echo "🔧 Installing shell completion..."
	@bin/openidx install-completion

profiler-http:
	@echo "Starting pprof HTTP server..."
	./bin/profiler http $(PORT)

#---------------------------------------------------------------------------
# Docker
#---------------------------------------------------------------------------

docker-build:
	@echo "🐳 Building Docker images..."
	@for service in $(SERVICES); do \
		echo "  Building $$service image..."; \
		$(DOCKER) build -t $(DOCKER_REGISTRY)/$$service:$(VERSION) \
			--build-arg VERSION=$(VERSION) \
			-f deployments/docker/Dockerfile.$$service .; \
	done
	$(DOCKER) build -t $(DOCKER_REGISTRY)/admin-console:$(VERSION) \
		--build-arg SRC_DIR=. \
		-f deployments/docker/Dockerfile.admin-console ./web/admin-console

docker-push:
	@echo "📤 Pushing Docker images..."
	@for service in $(SERVICES); do \
		$(DOCKER) push $(DOCKER_REGISTRY)/$$service:$(VERSION); \
	done
	$(DOCKER) push $(DOCKER_REGISTRY)/admin-console:$(VERSION)

docker-build-agent:
	@echo "Building openidx-agent Docker image..."
	docker build -t openidx/agent -f deployments/docker/Dockerfile.agent .

#---------------------------------------------------------------------------
# Kubernetes & Helm
#---------------------------------------------------------------------------

helm-deps:
	@echo "📦 Updating Helm dependencies..."
	$(HELM) dependency update deployments/kubernetes/helm/openidx

helm-lint:
	@echo "🔍 Linting Helm chart..."
	$(HELM) lint deployments/kubernetes/helm/openidx

helm-template:
	@echo "📄 Rendering Helm templates..."
	$(HELM) template openidx deployments/kubernetes/helm/openidx \
		--namespace $(NAMESPACE) \
		--values deployments/kubernetes/helm/openidx/values.yaml

helm-install:
	@echo "🚀 Installing OpenIDX..."
	$(HELM) upgrade --install openidx deployments/kubernetes/helm/openidx \
		--namespace $(NAMESPACE) \
		--create-namespace \
		--values deployments/kubernetes/helm/openidx/values.yaml \
		--wait

helm-uninstall:
	@echo "🗑️  Uninstalling OpenIDX..."
	$(HELM) uninstall openidx --namespace $(NAMESPACE)

helm-ingress-nginx:
	@echo "🌐 Installing HA ingress-nginx controller (≥2 replicas behind an NLB)..."
	$(HELM) repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
	$(HELM) repo update ingress-nginx
	$(HELM) upgrade --install ingress-nginx ingress-nginx/ingress-nginx \
		--namespace ingress-nginx \
		--create-namespace \
		--values deployments/kubernetes/ingress-nginx-values.yaml \
		--wait

k8s-apply:
	@echo "📦 Applying Kubernetes manifests..."
	$(KUBECTL) apply -k deployments/kubernetes/overlays/development

k8s-delete:
	@echo "🗑️  Deleting Kubernetes resources..."
	$(KUBECTL) delete -k deployments/kubernetes/overlays/development

#---------------------------------------------------------------------------
# Infrastructure
#---------------------------------------------------------------------------

tf-init:
	@echo "🏗️  Initializing Terraform..."
	cd deployments/terraform && terraform init

tf-plan:
	@echo "📋 Planning Terraform changes..."
	cd deployments/terraform && terraform plan -out=tfplan

tf-apply:
	@echo "🚀 Applying Terraform changes..."
	cd deployments/terraform && terraform apply tfplan

tf-destroy:
	@echo "💥 Destroying infrastructure..."
	cd deployments/terraform && terraform destroy

#---------------------------------------------------------------------------
# Code Generation
#---------------------------------------------------------------------------

generate:
	@echo "⚙️  Generating code..."
	$(GOCMD) generate ./...

swagger:
	@echo "📚 Generating Swagger documentation..."
	swag init -g cmd/admin-api/main.go -o api/swagger

proto:
	@echo "📝 Generating protobuf code..."
	protoc --go_out=. --go-grpc_out=. api/proto/*.proto

#---------------------------------------------------------------------------
# Documentation
#---------------------------------------------------------------------------

docs:
	@echo "📖 Building documentation..."
	cd docs && mkdocs build

docs-serve:
	@echo "📖 Serving documentation..."
	cd docs && mkdocs serve

#---------------------------------------------------------------------------
# Cleanup
#---------------------------------------------------------------------------

clean:
	@echo "🧹 Cleaning build artifacts..."
	rm -rf bin/
	rm -rf coverage.out coverage.html
	rm -rf web/admin-console/build
	rm -rf web/admin-console/node_modules

clean-docker:
	@echo "🐳 Cleaning Docker resources..."
	$(DOCKER) system prune -f

#---------------------------------------------------------------------------
# Security Scanning
#---------------------------------------------------------------------------

SCAN_SERVICES := identity-service governance-service provisioning-service audit-service admin-api oauth-service

.PHONY: scan-all scan-trivy scan-sbom scan-secrets scan-deps scan-fs scan-license scan-sast scan-config

scan-all: scan-trivy scan-sbom scan-secrets scan-deps scan-fs scan-sast
	@echo "✅ All security scans complete!"

scan-trivy:
	@echo "🔍 Running Trivy vulnerability scans..."
	@which trivy > /dev/null || (echo "Installing Trivy..." && go install github.com/aquasecurity/trivy/cmd/trivy@latest)
	@for service in $(SCAN_SERVICES); do \
		echo "  Scanning $$service..."; \
		trivy image --severity HIGH,CRITICAL --exit-code 0 \
			--format table --vuln-type os,library \
			$(DOCKER_REGISTRY)/$$service:$(VERSION) 2>&1 || echo "    Image not found or scan failed"; \
	done
	@echo "  Scanning admin-console..."
	trivy image --severity HIGH,CRITICAL --exit-code 0 \
		--format table --vuln-type os,library \
		$(DOCKER_REGISTRY)/admin-console:$(VERSION) 2>&1 || echo "    Image not found or scan failed"

scan-sbom:
	@echo "📋 Generating SBOMs..."
	@which syft > /dev/null || (echo "Installing Syft..." && go install github.com/anchore/syft/cmd/syft@latest)
	@mkdir -p sboms
	@for service in $(SCAN_SERVICES); do \
		echo "  Generating SBOM for $$service..."; \
		syft $(DOCKER_REGISTRY)/$$service:$(VERSION) \
			-o spdx-json > sboms/$$service-$(VERSION).spdx.json 2>/dev/null || echo "    Warning: Could not generate SBOM for $$service"; \
	done
	@echo "  Generating SBOM for admin-console..."
	syft $(DOCKER_REGISTRY)/admin-console:$(VERSION) \
		-o spdx-json > sboms/admin-console-$(VERSION).spdx.json 2>/dev/null || echo "    Warning: Could not generate SBOM for admin-console"
	@echo "  SBOMs saved to sboms/"

scan-secrets:
	@echo "🔐 Scanning for secrets..."
	@which gitleaks > /dev/null || (echo "Installing Gitleaks..." && go install github.com/gitleaks/gitleaks/v4/cmd/gitleaks@latest)
	gitleaks detect --source . --verbose --report-format json --report-name gitleaks-report.json || true

scan-deps:
	@echo "📦 Scanning dependencies..."
	@which govulncheck > /dev/null || (echo "Installing govulncheck..." && go install golang.org/x/vuln/cmd/govulncheck@latest)
	@echo "  Scanning Go dependencies..."
	govulncheck ./... || echo "    Warning: Vulnerabilities found in Go dependencies"
	@echo "  Scanning NPM dependencies..."
	cd web/admin-console && npm audit --audit-level=high || echo "    Warning: Vulnerabilities found in NPM dependencies"

scan-fs:
	@echo "🔍 Running Trivy filesystem scan..."
	@which trivy > /dev/null || (echo "Installing Trivy..." && go install github.com/aquasecurity/trivy/cmd/trivy@latest)
	trivy fs --severity HIGH,CRITICAL --format table --vuln-type library .

scan-license:
	@echo "📜 Checking license compliance..."
	@which go-licenses > /dev/null || (echo "Installing go-licenses..." && go install github.com/google/go-licenses@latest)
	@echo "  Checking Go licenses..."
	go-licenses check ./... --disallowed_types=forbidden,restricted || echo "    Warning: License issues found"

scan-sast:
	@echo "🔬 Running SAST scan with semgrep..."
	@which semgrep > /dev/null || (echo "Installing semgrep..." && python3 -m pip install semgrep || echo "    Warning: Could not install semgrep")
	@which semgrep > /dev/null && semgrep --config auto --json --output semgrep-report.json . || echo "    Warning: SAST scan failed"

scan-config:
	@echo "⚙️  Scanning configuration files..."
	@which trivy > /dev/null || (echo "Installing Trivy..." && go install github.com/aquasecurity/trivy/cmd/trivy@latest)
	trivy config --severity HIGH,CRITICAL --format table .

scan-report:
	@echo "📊 Generating security scan report..."
	@echo "OpenIDX Security Scan Report" > security-scan-report.txt
	@echo "Generated: $$(date)" >> security-scan-report.txt
	@echo "" >> security-scan-report.txt
	@echo "=== Trivy Image Scan ===" >> security-scan-report.txt
	@make scan-trivy >> security-scan-report.txt 2>&1 || true
	@echo "" >> security-scan-report.txt
	@echo "=== Dependency Scan ===" >> security-scan-report.txt
	@make scan-deps >> security-scan-report.txt 2>&1 || true
	@echo "" >> security-scan-report.txt
	@echo "=== Secret Scan ===" >> security-scan-report.txt
	@make scan-secrets >> security-scan-report.txt 2>&1 || true
	@echo "" >> security-scan-report.txt
	@echo "=== Filesystem Scan ===" >> security-scan-report.txt
	@make scan-fs >> security-scan-report.txt 2>&1 || true
	@echo "Report saved to security-scan-report.txt"

#---------------------------------------------------------------------------
# Release
#---------------------------------------------------------------------------

release: lint test build docker-build scan-trivy docker-push
	@echo "🎉 Release $(VERSION) complete!"

#---------------------------------------------------------------------------
# Help
#---------------------------------------------------------------------------

help:
	@echo "OpenIDX Makefile"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Development:"
	@echo "  deps           Install dependencies"
	@echo "  build          Build all services and web apps"
	@echo "  build-cli      Build the openidx CLI tool"
	@echo "  install-cli    Build and install CLI to \$GOPATH/bin or /usr/local/bin"
	@echo "  test           Run unit tests"
	@echo "  lint           Run linters"
	@echo "  dev            Start development environment"
	@echo "  dev-stop       Stop development environment"
	@echo ""
	@echo "CLI Usage (alternative to make):"
	@echo "  openidx dev              Start development environment"
	@echo "  openidx build            Build all services"
	@echo "  openidx test             Run tests"
	@echo "  openidx migrate up       Run migrations"
	@echo "  openidx seed             Seed test data"
	@echo "  openidx status           Show service status"
	@echo "  openidx logs [service]   View logs"
	@echo "  openidx cleanup          Stop and clean up"
	@echo "  openidx doctor           Check environment"
	@echo "  openidx --help           Show all commands"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  deps           Install dependencies"
	@echo "  build          Build all services and web apps"
	@echo "  build-profiler Build profiler CLI tool"
	@echo "  test           Run unit tests"
	@echo "  lint           Run linters"
	@echo "  dev            Start development environment"
	@echo "  dev-stop       Stop development environment"
	@echo "  docker-build   Build Docker images"
	@echo "  docker-push    Push Docker images"
	@echo "  helm-install   Install via Helm"
	@echo "  clean          Clean build artifacts"
	@echo ""
	@echo "Profiling:"
	@echo "  build-profiler Build the profiler CLI tool"
	@echo "  profiler-cpu   Capture CPU profile (SERVICE=name DURATION=30s)"
	@echo "  profiler-mem   Capture memory profile (SERVICE=name)"
	@echo "  profiler-trace Capture execution trace (SERVICE=name DURATION=5s)"
	@echo "  profiler-flame Generate flame graph (PROFILE=cpu.prof)"
	@echo "  profiler-http  Start pprof HTTP server (PORT=6060)"
	@echo ""
	@echo "Security Scanning:"
	@echo "  scan-all       Run all security scans"
	@echo "  scan-trivy     Run Trivy vulnerability scanner on images"
	@echo "  scan-sbom      Generate SBOMs for all images"
	@echo "  scan-secrets   Scan for secrets with gitleaks"
	@echo "  scan-deps      Scan dependencies for vulnerabilities"
	@echo "  scan-fs        Run filesystem vulnerability scan"
	@echo "  scan-license   Check license compliance"
	@echo "  scan-sast      Run SAST scan with semgrep"
	@echo "  scan-config    Scan configuration files"
	@echo "  scan-report    Generate combined security report"
	@echo ""
	@echo "  help           Show this help"
