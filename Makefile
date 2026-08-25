SHELL := /bin/bash
GO ?= go

# Container image build settings.
#
# REGISTRY: image base path. Each role image is published at
# `$(REGISTRY)/<role>:$(VERSION)` — matches the Helm chart's
# `image.registry` default (deploy/charts/constellation/values.yaml) and
# the resolution in templates/_helpers.tpl `constellation.roleImage`.
# Override to push to your own org: `make images-push REGISTRY=ghcr.io/your-org/constellation`.
#
# NOTE: pre-2026-05 builds used `$(REGISTRY)/constellation-<role>` (hyphen).
# The chart never matched that pattern — installs ErrImagePulled unless the
# image was hand-retagged. Aligned 2026-05-14.
REGISTRY ?= ghcr.io/alphabravo-oss/constellation
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
# PLATFORMS is the buildx target list. The local `--load` image-* targets only
# work with a SINGLE platform (docker can't load a manifest list), so for local
# dev builds pass one arch, e.g. `make image-api PLATFORMS=linux/amd64`.
# RELEASE_PLATFORMS (below) is the qualified platform list used for pushes.
PLATFORMS ?= linux/amd64
# Application and release images intentionally target the amd64 server fleet.
# Add another architecture only after its runtime-agent/native dependencies are
# separately qualified.
RELEASE_PLATFORMS ?= linux/amd64
# FIPS=true toggles GOFIPS140=v1.0.0 + -tags fips inside the relevant
# Dockerfiles (currently runtime-agent; api/scanner/operator use the separate
# Dockerfile.fips path). Default off — passing it through as a build-arg is
# cheap and lets `make image-runtime-agent FIPS=true` Just Work.
FIPS ?= 0
DOCKER_BUILD ?= docker buildx build --platform $(PLATFORMS) --build-arg VERSION=$(VERSION) --build-arg FIPS=$(FIPS)

.PHONY: all build test lint migrate helm-lint helm-template-smoke frontend-build verify \
        deploy deploy-dryrun undeploy values-prod \
        images images-push release-images image-api image-scanner image-operator image-discoverer image-audit-archiver image-frontend image-runtime-agent image-admission image-migrate image-bootstrap image-postgres release-check \
        dp dp-clean vendor-neuvector-diff vendor-neuvector-sync \
        compose-up compose-down compose-logs compose-images compose-images-core \
        compose-image-api compose-image-scanner compose-image-operator compose-image-frontend \
        compose-image-seed compose-image-discoverer compose-image-scanner-driver \
        compose-image-runtime-agent compose-image-go-dev test-e2e \
        install-systemd install-systemd-user uninstall-systemd

all: build test lint

build:
	$(GO) build ./...

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

lint:
	@command -v golangci-lint >/dev/null && golangci-lint run || echo "golangci-lint not installed; skipping"

migrate:
	@command -v goose >/dev/null || (echo "install goose: https://github.com/pressly/goose" && exit 1)
	goose -dir db/migrations postgres "$$DATABASE_URL" up

helm-lint:
	helm lint deploy/charts/constellation

helm-install-dry:
	helm install --dry-run constellation deploy/charts/constellation

# helm-template-smoke renders the chart against several common value combos to
# catch goofs that don't surface with the default-only `helm lint` pass.
helm-template-smoke:
	@echo ">> default values"
	@helm template constellation deploy/charts/constellation/ > /dev/null
	@echo ">> ingress enabled"
	@helm template constellation deploy/charts/constellation/ --set ingress.enabled=true > /dev/null
	@echo ">> external postgres"
	@helm template constellation deploy/charts/constellation/ --set postgres.embedded=false --set postgres.dsn=postgres://x:y@host/db > /dev/null
	@echo ">> fips mode"
	@helm template constellation deploy/charts/constellation/ --set fips.enabled=true > /dev/null
	@echo ">> cert-manager TLS"
	@helm template constellation deploy/charts/constellation/ --set tls.certManager.enabled=true --set tls.certManager.issuer=letsencrypt-prod > /dev/null
	@echo ">> three-node k3s HA profile"
	@./scripts/test-helm-ha.sh
	@echo "helm-template-smoke: ok"

# -----------------------------------------------------------------------------
# Helm deploy targets (production K8s path)
# -----------------------------------------------------------------------------
# Override any of these on the command line:
#   make deploy CLUSTER=eks-prod NS=constellation-system VALUES=ops/values-prod.yaml RELEASE=constellation
CLUSTER ?=
NS      ?= constellation-system
RELEASE ?= constellation
VALUES  ?= deploy/charts/constellation/values.yaml
HELM_KCONTEXT = $(if $(CLUSTER),--kube-context $(CLUSTER),)

deploy:
	helm upgrade --install $(RELEASE) deploy/charts/constellation \
		-n $(NS) --create-namespace $(HELM_KCONTEXT) -f $(VALUES)

deploy-dryrun:
	helm upgrade --install $(RELEASE) deploy/charts/constellation \
		-n $(NS) --create-namespace $(HELM_KCONTEXT) -f $(VALUES) --dry-run --debug

undeploy:
	helm uninstall $(RELEASE) -n $(NS) $(HELM_KCONTEXT)

# values-prod renders a sample production values file at ops/values-prod.yaml.
values-prod:
	@mkdir -p ops
	@cp deploy/charts/constellation/examples/values-prod.yaml ops/values-prod.yaml
	@echo "Wrote ops/values-prod.yaml. Edit before applying."

frontend-build:
	cd frontend && npm ci && npm run build

frontend-test:
	cd frontend && npm test --silent

verify: vet test lint helm-lint
	@echo "Phase 1 verification: green if no error printed above."

# -----------------------------------------------------------------------------
# Container images — one per scaling-unit role.
# Build locally:   make images
# Push:            make images-push REGISTRY=ghcr.io/your-org
# -----------------------------------------------------------------------------

images: image-api image-scanner image-operator image-discoverer image-audit-archiver image-frontend image-runtime-agent image-admission image-migrate image-bootstrap image-postgres

image-api:
	$(DOCKER_BUILD) -f deploy/docker/Dockerfile.api      -t $(REGISTRY)/api:$(VERSION)      --load .

# image-scanner: SLIM by default (~780MB) — vuln DBs fetched at runtime.
image-scanner:
	$(DOCKER_BUILD) -f deploy/docker/Dockerfile.scanner  -t $(REGISTRY)/scanner:$(VERSION)  --load .

# image-scanner-airgap: fat variant (~4.6GB) with Trivy+Grype DBs baked in, for
# air-gapped clusters that must scan on first boot with no network. Tagged -airgap.
image-scanner-airgap:
	$(DOCKER_BUILD) --build-arg BAKE_VULN_DB=1 -f deploy/docker/Dockerfile.scanner -t $(REGISTRY)/scanner:$(VERSION)-airgap --load .

image-operator:
	$(DOCKER_BUILD) -f deploy/docker/Dockerfile.operator -t $(REGISTRY)/operator:$(VERSION) --load .

image-discoverer:
	$(DOCKER_BUILD) -f deploy/docker/Dockerfile.discoverer -t $(REGISTRY)/discoverer:$(VERSION) --load .

# image-audit-archiver: chart role key is `auditArchiver` which resolves
# to image path `audit-archiver` via the helper's kebab-case rule.
image-audit-archiver:
	$(DOCKER_BUILD) -f deploy/docker/Dockerfile.archiver -t $(REGISTRY)/audit-archiver:$(VERSION) --load .

image-frontend:
	$(DOCKER_BUILD) -f deploy/docker/Dockerfile.frontend -t $(REGISTRY)/frontend:$(VERSION) --load .

# image-admission builds the constellation-admission ValidatingAdmissionWebhook
# server image. Deployed by the Helm chart's admission-deployment template;
# without this, `helm install` produces ErrImagePull for the admission pod.
image-admission:
	$(DOCKER_BUILD) -f deploy/docker/Dockerfile.admission -t $(REGISTRY)/admission:$(VERSION) --load .

# image-migrate builds the goose-based migration image consumed by the
# pre-install migrate Job. Without it `helm install` ErrImagePulls.
image-migrate:
	$(DOCKER_BUILD) -f deploy/docker/Dockerfile.migrate -t $(REGISTRY)/migrate:$(VERSION) --load .

# image-kube-bench-runner builds the opt-in CIS benchmark runner image. It
# bundles the upstream kube-bench binary (see Dockerfile) plus the thin
# constellation-kube-bench-runner that POSTs results to the ingest endpoint.
# Not part of `images` because it's opt-in (kubeBenchRunner.enabled=false).
image-kube-bench-runner:
	$(DOCKER_BUILD) -f deploy/docker/Dockerfile.kube-bench-runner -t $(REGISTRY)/kube-bench-runner:$(VERSION) --load .

# image-bootstrap builds the one-shot admin-seed image consumed by a Helm
# post-install Hook. Without it a fresh install has no way to log in
# until someone provisions a user out of band.
image-bootstrap:
	$(DOCKER_BUILD) -f deploy/docker/Dockerfile.bootstrap -t $(REGISTRY)/bootstrap:$(VERSION) --load .

image-postgres:
	$(DOCKER_BUILD) -f deploy/docker/Dockerfile.postgres -t $(REGISTRY)/postgres:$(VERSION) --load .

	# image-runtime-agent supports FIPS=true: the resulting image is tagged
	# `:$(VERSION)-fips` so an environment that needs the FIPS build doesn't
	# clobber the production tag.
# FIPS toggles the Go agent's crypto path only — see docs/fips.md#runtime-agent
# for the precise scoping (dp / hyperscan are explicitly non-FIPS).
image-runtime-agent:
ifeq ($(FIPS),true)
	$(DOCKER_BUILD) -f deploy/docker/Dockerfile.runtime-agent -t $(REGISTRY)/runtime-agent:$(VERSION)-fips --load .
else ifeq ($(FIPS),1)
	$(DOCKER_BUILD) -f deploy/docker/Dockerfile.runtime-agent -t $(REGISTRY)/runtime-agent:$(VERSION)-fips --load .
else
	$(DOCKER_BUILD) -f deploy/docker/Dockerfile.runtime-agent -t $(REGISTRY)/runtime-agent:$(VERSION) --load .
endif

# dp — standalone build of the vendored NeuVector C data-plane out of container,
# for fast dev iteration. Requires host packages: build-essential pkg-config
# libnetfilter-queue-dev libnfnetlink-dev libmnl-dev libpcap-dev libpcre2-dev
# libhyperscan-dev libjansson-dev libjemalloc-dev liburcu-dev. The Dockerfile
# build (image-runtime-agent) is the canonical path — use this target only when
# you're iterating on a specific dp source change.
dp:
	$(MAKE) -C third_party/neuvector/dp -j"$$(nproc)"

dp-clean:
	$(MAKE) -C third_party/neuvector/dp clean

# vendor-neuvector-diff: read-only report. Shows any drift between the
# files in third_party/neuvector/ and a clean checkout at the rev recorded
# in NOTICE. Exit 0 means clean; exit 2 means drift (a unified diff is
# written to stdout). CI should run this and fail the build on exit 2.
vendor-neuvector-diff:
	@./scripts/sync-neuvector.sh --diff

# vendor-neuvector-sync: re-vendor third_party/neuvector/ at the requested
# revision. Captures any pre-existing drift as a patch under
# local-patches/, re-applies it after the swap, refreshes NOTICE, and
# validates with `make dp` before declaring success. Use BUILD=image to
# do a full image build instead (slow; only needed when changing
# Dockerfile.runtime-agent's package set).
#   make vendor-neuvector-sync REV=v5.6.0
#   make vendor-neuvector-sync REV=4247e245 BUILD=image
#   make vendor-neuvector-sync REV=main UPSTREAM=../neuvector
REV ?=
BUILD ?= dp
UPSTREAM ?=
vendor-neuvector-sync:
	@test -n "$(REV)" || (echo "REV=<git-ref> is required (e.g. make vendor-neuvector-sync REV=v5.6.0)" && exit 1)
	@./scripts/sync-neuvector.sh --sync --rev "$(REV)" --build "$(BUILD)" $(if $(UPSTREAM),--upstream "$(UPSTREAM)")

images-push:
	$(DOCKER_BUILD) -f deploy/docker/Dockerfile.api           -t $(REGISTRY)/api:$(VERSION)            --push .
	$(DOCKER_BUILD) -f deploy/docker/Dockerfile.scanner       -t $(REGISTRY)/scanner:$(VERSION)        --push .
	$(DOCKER_BUILD) -f deploy/docker/Dockerfile.operator      -t $(REGISTRY)/operator:$(VERSION)       --push .
	$(DOCKER_BUILD) -f deploy/docker/Dockerfile.discoverer    -t $(REGISTRY)/discoverer:$(VERSION)     --push .
	$(DOCKER_BUILD) -f deploy/docker/Dockerfile.archiver      -t $(REGISTRY)/audit-archiver:$(VERSION) --push .
	$(DOCKER_BUILD) -f deploy/docker/Dockerfile.frontend      -t $(REGISTRY)/frontend:$(VERSION)       --push .
	$(DOCKER_BUILD) -f deploy/docker/Dockerfile.admission     -t $(REGISTRY)/admission:$(VERSION)      --push .
	$(DOCKER_BUILD) -f deploy/docker/Dockerfile.migrate       -t $(REGISTRY)/migrate:$(VERSION)        --push .
	$(DOCKER_BUILD) -f deploy/docker/Dockerfile.bootstrap     -t $(REGISTRY)/bootstrap:$(VERSION)      --push .
	$(DOCKER_BUILD) -f deploy/docker/Dockerfile.runtime-agent -t $(REGISTRY)/runtime-agent:$(VERSION)  --push .
	$(DOCKER_BUILD) -f deploy/docker/Dockerfile.postgres      -t $(REGISTRY)/postgres:$(VERSION)       --push .

# release-images uses the explicitly qualified release platform set (amd64).
release-images:
	$(MAKE) images-push PLATFORMS="$(RELEASE_PLATFORMS)"

release-check:
	./scripts/verify-release.sh "$(VERSION)"

compose-up:
	docker compose up -d --build

compose-down:
	docker compose down -v

compose-logs:
	docker compose logs -f

# -----------------------------------------------------------------------------
# compose-images — pre-build every image referenced by docker-compose.yaml as
# constellation/<role>:dev. The compose file references these tags by default so
# `docker compose up` boots WITHOUT additional registry pulls on a fresh checkout.
#
# Build subset: api, scanner, operator, frontend (the always-up services), plus
# the wave-K2 newcomers: seed, discoverer, scanner-driver, runtime-agent.
# go-dev is built lazily by compose.dev.yaml only.
#
# Usage:
#   make compose-images           # all roles (single-arch, local docker)
#   make compose-image-api        # just one role
#   PLATFORMS=linux/amd64 make compose-images   # cross-build with buildx
# -----------------------------------------------------------------------------
COMPOSE_BUILD ?= docker build

compose-images: compose-images-core compose-image-seed compose-image-discoverer \
                compose-image-scanner-driver compose-image-runtime-agent

compose-images-core: compose-image-api compose-image-scanner compose-image-operator \
                     compose-image-frontend

compose-image-api:
	$(COMPOSE_BUILD) -f deploy/docker/Dockerfile.api      -t constellation/api:dev      .

compose-image-scanner:
	$(COMPOSE_BUILD) -f deploy/docker/Dockerfile.scanner  -t constellation/scanner:dev  .

compose-image-operator:
	$(COMPOSE_BUILD) -f deploy/docker/Dockerfile.operator -t constellation/operator:dev .

compose-image-frontend:
	$(COMPOSE_BUILD) -f deploy/docker/Dockerfile.frontend -t constellation/frontend:dev .

compose-image-seed:
	$(COMPOSE_BUILD) -f deploy/docker/Dockerfile.seed             -t constellation/seed:dev             .

compose-image-discoverer:
	$(COMPOSE_BUILD) -f deploy/docker/Dockerfile.discoverer       -t constellation/discoverer:dev       .

compose-image-scanner-driver:
	$(COMPOSE_BUILD) -f deploy/docker/Dockerfile.scanner-driver   -t constellation/scanner-driver:dev   .

compose-image-runtime-agent:
	$(COMPOSE_BUILD) -f deploy/docker/Dockerfile.runtime-agent    -t constellation/runtime-agent:dev    .

compose-image-go-dev:
	$(COMPOSE_BUILD) -f deploy/docker/Dockerfile.go-dev           -t constellation/go-dev:dev           .

test-e2e:
	cd frontend && npx playwright test

# -----------------------------------------------------------------------------
# Native systemd packaging — see deploy/systemd/ and docs/deployment-systemd.md.
# Dev convenience target: builds every binary, then runs the installer in
# --from-source mode. Use SYSTEMD_ROLES=... to skip the interactive prompt:
#
#   sudo make install-systemd SYSTEMD_ROLES=api,scanner \
#        SYSTEMD_DATABASE_URL=postgres://...
#
# Unprivileged developer install (no sudo, ~/.config/systemd/user):
#
#   make install-systemd-user SYSTEMD_ROLES=api SYSTEMD_LISTEN_ADDR=:18081
#
# -----------------------------------------------------------------------------
SYSTEMD_ROLES ?=
SYSTEMD_DATABASE_URL ?=
SYSTEMD_LISTEN_ADDR ?=

install-systemd:
	$(GO) build ./cmd/... ./deploy/e2e/scanner-driver
	@bash deploy/systemd/install.sh --from-source \
	  $(if $(SYSTEMD_ROLES),--non-interactive --roles=$(SYSTEMD_ROLES)) \
	  $(if $(SYSTEMD_DATABASE_URL),--database-url=$(SYSTEMD_DATABASE_URL)) \
	  $(if $(SYSTEMD_LISTEN_ADDR),--listen-addr=$(SYSTEMD_LISTEN_ADDR))

install-systemd-user:
	$(GO) build ./cmd/... ./deploy/e2e/scanner-driver
	@bash deploy/systemd/install.sh --user --from-source \
	  $(if $(SYSTEMD_ROLES),--non-interactive --roles=$(SYSTEMD_ROLES)) \
	  $(if $(SYSTEMD_DATABASE_URL),--database-url=$(SYSTEMD_DATABASE_URL)) \
	  $(if $(SYSTEMD_LISTEN_ADDR),--listen-addr=$(SYSTEMD_LISTEN_ADDR))

uninstall-systemd:
	@bash deploy/systemd/uninstall.sh $(if $(PURGE),--purge)
