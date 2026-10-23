# Constellation — single orchestrator for build, test, lint, generate, images and the dev loop.
# Target set follows the AlphaBravo Technology Selection Guide (ch.04 "Make-driven dev orchestration").
SHELL := /bin/bash
.DEFAULT_GOAL := help

GO            ?= go
GOLANGCI_LINT ?= golangci-lint
GOTESTSUM     ?= gotestsum
export GOWORK := off

MODULE       := github.com/alphabravocompany/constellation
GO_VERSION   := $(shell awk '/^go /{print $$2}' go.mod)
NODE_VERSION ?= $(shell cat .node-version)

# Build-time identity. `?=` so CI can override from the environment.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null || echo dev)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GO_LDFLAGS := -s -w \
  -X $(MODULE)/pkg/version.Version=$(VERSION) \
  -X $(MODULE)/pkg/version.Commit=$(COMMIT) \
  -X $(MODULE)/pkg/version.BuildTime=$(DATE)

# Every production binary under cmd/. Adding a binary is a one-line edit here.
BINARIES := constellation-api constellation-scanner constellation-operator constellation-discoverer \
  constellation-runtime-agent constellation-admission constellation-backup \
  constellation-restore constellation-seed constellation-compliance-scheduler constellation-github-app \
  constellation-k8s-compliance-collector constellation-kube-bench-runner constellation-netpolicy-applier \
  constellation-registry-walker constellation-support-bundle-verify constellationctl audit-archiver \
  checkov-plugin sample-scanner-plugin
TOOLS := release-gate sarif-tool scanner-tools

ARTIFACT_DIR ?= artifacts
REGISTRY     ?= ghcr.io/alphabravo-oss/constellation
PLATFORMS    ?= linux/amd64
FIPS         ?= 0
DOCKER_BUILD ?= docker buildx build --platform $(PLATFORMS) \
  --build-arg GO_VERSION=$(GO_VERSION) --build-arg VERSION=$(VERSION) \
  --build-arg COMMIT=$(COMMIT) --build-arg BUILD_TIME=$(DATE) --build-arg FIPS=$(FIPS)

IMAGES := api scanner operator discoverer audit-archiver frontend runtime-agent admission \
  postgres compliance-scheduler kube-bench-runner toolbox
# Dockerfile name differs from the image name for these roles.
dockerfile_audit-archiver := archiver

.PHONY: help dev dev-down dev-status dev-logs build tools-build test test-integration lint vet fmt fmt-fix \
  generate migrate bench check security updates fips-build fips-test helm-lint helm-template-smoke \
  e2e frontend-build frontend-lint frontend-test lint-shell check-go-version tools images images-push \
  release-images release-check deploy deploy-dryrun undeploy dp dp-clean vendor-neuvector-diff \
  vendor-neuvector-sync clean $(addprefix image-,$(IMAGES)) image-scanner-airgap

help: ## List targets
	@grep -E '^[a-zA-Z0-9_%-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*## "}{printf "  %-24s %s\n",$$1,$$2}'

# ---------------------------------------------------------------------------
# Dev loop (scripts/dev.sh: Postgres + observability compose, Air x3, Vite)
# ---------------------------------------------------------------------------
dev: ## Start the full local stack (Postgres, api, operator, scanner, web, Grafana stack)
	@scripts/dev.sh up
dev-down: ## Stop the local stack
	@scripts/dev.sh down
dev-status: ## Show local stack status
	@scripts/dev.sh status
dev-logs: ## Tail local stack logs
	@scripts/dev.sh logs

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
build: check-go-version $(addprefix bin/,$(BINARIES)) ## Build every production binary into bin/
tools-build: $(addprefix bin/,$(TOOLS)) ## Build the release/CI helper tools into bin/

bin/%: ## Build one binary: make bin/constellation-api
	@mkdir -p bin
	@if [ -d cmd/$* ]; then src=./cmd/$*; else src=./cmd/tools/$*; fi; \
	echo ">> go build $$src"; \
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(GO_LDFLAGS)" -o $@ $$src

check-go-version: ## Fail when any Dockerfile hard-codes a Go version that is not go.mod's
	@bad=$$(grep -lE 'golang:[0-9]+\.[0-9]+' deploy/docker/Dockerfile.* 2>/dev/null || true); \
	if [ -n "$$bad" ]; then echo "Dockerfiles must take the Go version from ARG GO_VERSION (go.mod = $(GO_VERSION)):"; echo "$$bad"; exit 1; fi

# ---------------------------------------------------------------------------
# Quality gates
# ---------------------------------------------------------------------------
test: ## Unit tests (no Docker) via gotestsum with JUnit output
	@mkdir -p $(ARTIFACT_DIR)
	$(GOTESTSUM) --junitfile $(ARTIFACT_DIR)/unit.xml --jsonfile $(ARTIFACT_DIR)/unit.json \
	  -- -race -shuffle=on -count=1 ./...

# //go:build integration tests. internal/testutil/pgtest starts one pgvector
# container per test process (Docker, or CONSTELLATION_TEST_DATABASE_URL) and
# clones a migrated template database per test, so packages run in parallel.
TEST_INTEGRATION_P ?= 8
PKG ?= ./...
test-integration: ## Integration tests against real Postgres (testcontainers + pgtestdb)
	@mkdir -p $(ARTIFACT_DIR)
	$(GOTESTSUM) --junitfile $(ARTIFACT_DIR)/integration.xml --jsonfile $(ARTIFACT_DIR)/integration.json \
	  -- -tags=integration -race -shuffle=on -count=1 -p $(TEST_INTEGRATION_P) $(PKG)

lint: ## golangci-lint (config: .golangci.yml)
	@mkdir -p $(ARTIFACT_DIR)
	$(GOLANGCI_LINT) run --output.json.path=$(ARTIFACT_DIR)/golangci-lint.json ./...

vet: ## go vet
	$(GO) vet ./...

fmt: ## Verify formatting (gofmt + goimports); never rewrites files
	@out=$$($(GOLANGCI_LINT) fmt --diff ./... 2>&1); if [ -n "$$out" ]; then echo "$$out"; echo "run: make fmt-fix"; exit 1; fi

fmt-fix: ## Rewrite files with gofmt + goimports
	$(GOLANGCI_LINT) fmt ./...

lint-shell: ## shellcheck every tracked shell script
	bash scripts/lint-shell.sh

frontend-lint: frontend/node_modules/.package-lock.json ## eslint + tsc for the frontend
	cd frontend && npm run lint && npm run type-check

frontend-test: frontend/node_modules/.package-lock.json ## vitest
	cd frontend && npm test --silent

frontend/node_modules/.package-lock.json: frontend/package.json frontend/package-lock.json
	cd frontend && npm ci --no-audit --no-fund

frontend-build: frontend/node_modules/.package-lock.json ## Production bundle and initial JavaScript budget
	cd frontend && npm run build

generate: ## Regenerate code (controller-gen deepcopy for the operator CRDs); sqlc/buf join in Phase 2
	$(GO) generate ./...

bench: ## Hot HTTP handlers on 10k rows (real disposable Postgres) and shared RP
	$(GO) test -tags=integration -run='^$$' -bench=BenchmarkEfficiencyHandlers -benchmem ./internal/server
	$(GO) test -run='^$$' -bench=BenchmarkOIDC -benchmem ./internal/identity

check: lint vet fmt lint-shell frontend-lint frontend-build test ## Composite quality gate

security: ## gosec + govulncheck + gitleaks (SARIF under artifacts/)
	bash scripts/security-scan.sh gosec
	bash scripts/security-scan.sh govulncheck
	bash scripts/security-scan.sh gitleaks

updates: ## List available Go module and npm updates
	$(GO) list -u -m all 2>/dev/null | grep '\[' || true
	cd frontend && npm outdated || true

tools: ## Install pinned CI tools into ~/.local/bin
	bash scripts/install-ci-tools.sh

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
migrate: ## Apply pending embedded migrations to $$DATABASE_URL (same runner the API uses on boot)
	$(GO) run ./cmd/constellation-api --migrate-only

# ---------------------------------------------------------------------------
# FIPS (Go native FIPS 140-3 module; see ADR 0004)
# ---------------------------------------------------------------------------
fips-build: ## Build the API, scanner and operator with GOFIPS140=v1.0.0 -tags fips into bin/fips/
	@mkdir -p bin/fips
	@for b in constellation-api constellation-scanner constellation-operator constellation-runtime-agent; do \
	  echo ">> fips build $$b"; \
	  GOFIPS140=v1.0.0 CGO_ENABLED=0 $(GO) build -trimpath -tags fips -ldflags="$(GO_LDFLAGS)" -o bin/fips/$$b ./cmd/$$b || exit 1; \
	done
fips-test: ## FIPS evidence run
	bash scripts/test-fips.sh

# ---------------------------------------------------------------------------
# Helm
# ---------------------------------------------------------------------------
helm-lint: ## helm lint the chart
	helm lint deploy/charts/constellation

helm-template-smoke: ## Render the chart against common value combinations
	@echo ">> default values"; helm template constellation deploy/charts/constellation/ > /dev/null
	@echo ">> ingress enabled"; helm template constellation deploy/charts/constellation/ --set ingress.enabled=true > /dev/null
	@echo ">> external postgres"; helm template constellation deploy/charts/constellation/ --set postgres.mode=external --set postgres.dsn=postgres://x:y@host/db > /dev/null
	@echo ">> fips mode"; helm template constellation deploy/charts/constellation/ --set fips.enabled=true > /dev/null
	@echo ">> cert-manager TLS"; helm template constellation deploy/charts/constellation/ --set tls.certManager.enabled=true --set tls.certManager.issuer=letsencrypt-prod > /dev/null
	@echo ">> object-store backups"; helm template constellation deploy/charts/constellation/ --set backup.objectStore.enabled=true > /dev/null
	@echo ">> three-node k3s HA profile"; ./scripts/test-helm-ha.sh
	@./scripts/test-helm-identity.sh
	@./scripts/test-helm-admission.sh
	@echo "helm-template-smoke: ok"

CLUSTER ?=
NS      ?= constellation-system
RELEASE ?= constellation
VALUES  ?= deploy/charts/constellation/values.yaml
HELM_KCONTEXT = $(if $(CLUSTER),--kube-context $(CLUSTER),)
deploy: ## helm upgrade --install (NS, RELEASE, VALUES, CLUSTER overridable)
	helm upgrade --install $(RELEASE) deploy/charts/constellation -n $(NS) --create-namespace $(HELM_KCONTEXT) -f $(VALUES)
deploy-dryrun: ## helm upgrade --install --dry-run
	helm upgrade --install $(RELEASE) deploy/charts/constellation -n $(NS) --create-namespace $(HELM_KCONTEXT) -f $(VALUES) --dry-run --debug
undeploy: ## helm uninstall
	helm uninstall $(RELEASE) -n $(NS) $(HELM_KCONTEXT)

# ---------------------------------------------------------------------------
# End-to-end
# ---------------------------------------------------------------------------
e2e: ## Playwright suite (PLAYWRIGHT_BASE_URL / VITE_API_URL select the target)
	cd frontend && npx playwright test

# ---------------------------------------------------------------------------
# Container images — one per scaling-unit role. GO_VERSION always comes from go.mod.
# ---------------------------------------------------------------------------
images: $(addprefix image-,$(IMAGES)) ## Build every role image locally (--load)

# Static pattern rule: image-<role> targets are .PHONY, and GNU make skips implicit
# pattern rules for phony targets, so the pattern must be declared statically.
$(addprefix image-,$(IMAGES)): image-%: check-go-version
	$(DOCKER_BUILD) $(if $(filter frontend,$*),--build-arg NODE_VERSION=$(NODE_VERSION)) \
	  -f deploy/docker/Dockerfile.$(or $(dockerfile_$*),$*) -t $(REGISTRY)/$*:$(VERSION)$(if $(filter 1 true,$(FIPS)),-fips) --load .

image-scanner-airgap: check-go-version ## Scanner image with Trivy + Grype DBs baked in (~4.6 GB)
	$(DOCKER_BUILD) --build-arg BAKE_VULN_DB=1 -f deploy/docker/Dockerfile.scanner -t $(REGISTRY)/scanner:$(VERSION)-airgap --load .

images-push: check-go-version ## Build and push every role image
	@for img in $(IMAGES); do \
	  df=$$img; [ "$$img" = audit-archiver ] && df=archiver; \
	  extra=""; [ "$$img" = frontend ] && extra="--build-arg NODE_VERSION=$(NODE_VERSION)"; \
	  echo ">> push $$img"; \
	  $(DOCKER_BUILD) $$extra -f deploy/docker/Dockerfile.$$df -t $(REGISTRY)/$$img:$(VERSION) --push . || exit 1; \
	done

release-images: ## Push the qualified release platform set
	$(MAKE) images-push PLATFORMS=linux/amd64

release-check: ## Verify a published release
	./scripts/verify-release.sh "$(VERSION)"

# ---------------------------------------------------------------------------
# Vendored NeuVector data-plane (ADR 0003)
# ---------------------------------------------------------------------------
dp: ## Build the C data-plane out of container (needs host dev packages, see third_party/neuvector/README.md)
	$(MAKE) -C third_party/neuvector/dp -j"$$(nproc)"
dp-clean:
	$(MAKE) -C third_party/neuvector/dp clean
vendor-neuvector-diff: ## Report drift between third_party/neuvector and the recorded upstream revision
	@./scripts/sync-neuvector.sh --diff
REV ?=
BUILD ?= dp
UPSTREAM ?=
vendor-neuvector-sync: ## Re-vendor third_party/neuvector at REV=<git-ref>
	@test -n "$(REV)" || (echo "REV=<git-ref> is required" && exit 1)
	@./scripts/sync-neuvector.sh --sync --rev "$(REV)" --build "$(BUILD)" $(if $(UPSTREAM),--upstream "$(UPSTREAM)")

clean: ## Remove build output
	rm -rf bin tmp $(ARTIFACT_DIR)
