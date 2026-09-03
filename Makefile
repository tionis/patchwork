# Patchwork development, verification, and OCI image targets.

IMAGE_NAME ?= patchwork
IMAGE_TAG ?= latest
REGISTRY ?= ghcr.io/tionis
PLATFORMS ?= linux/amd64,linux/arm64
CONTAINER_TOOL ?= podman
HOST_ARCH ?= $(shell uname -m | sed -e 's/^x86_64$$/amd64/' -e 's/^aarch64$$/arm64/')
DOCKERFILE ?= Dockerfile
MANIFEST_NAME ?= localhost/patchwork-manifest
GO ?= go
GO_TEST_FLAGS ?= -mod=vendor -timeout=90s
COVERAGE_MIN ?= 70
VERSION ?= dev
COMMIT ?= unknown
BUILD_DATE ?= unknown

ifdef REGISTRY
FULL_IMAGE_NAME = $(REGISTRY)/$(IMAGE_NAME)
else
FULL_IMAGE_NAME = $(IMAGE_NAME)
endif

CONTAINER_BUILD_ARGS = \
	--build-arg VERSION=$(VERSION) \
	--build-arg COMMIT=$(COMMIT) \
	--build-arg DATE=$(BUILD_DATE) \
	--file $(DOCKERFILE)

.PHONY: help
help: ## Show available targets
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "  %-26s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: fmt-check
fmt-check: ## Verify that tracked Go files are formatted
	@files="$$(gofmt -l $$(git ls-files '*.go' ':!vendor/**'))"; \
		test -z "$$files" || { echo "Unformatted Go files:"; echo "$$files"; exit 1; }

.PHONY: vet
vet: ## Run Go static analysis against vendored dependencies
	$(GO) vet -mod=vendor ./...

.PHONY: test
test: ## Run the shuffled test suite
	$(GO) test $(GO_TEST_FLAGS) -shuffle=on ./...

.PHONY: test-race
test-race: ## Run all tests with the race detector
	$(GO) test $(GO_TEST_FLAGS) -race -shuffle=on ./...

.PHONY: test-stress
test-stress: ## Repeatedly stress relay concurrency
	$(GO) test $(GO_TEST_FLAGS) -race -shuffle=on -count=100 ./internal/relay

.PHONY: test-cover
test-cover: ## Enforce statement coverage and write coverage.out
	$(GO) test $(GO_TEST_FLAGS) -coverprofile=coverage.out ./...
	@total="$$( $(GO) tool cover -func=coverage.out | awk '/^total:/ {gsub("%", "", $$3); print $$3}' )"; \
		echo "Total coverage: $$total%"; \
		awk -v total="$$total" -v minimum="$(COVERAGE_MIN)" 'BEGIN { exit !(total >= minimum) }'

.PHONY: verify
verify: fmt-check vet test-race test-cover ## Run the complete local/CI verification suite

.PHONY: build-local
build-local: ## Build the Go binary locally
	CGO_ENABLED=0 $(GO) build -mod=vendor -trimpath -o patchwork .

.PHONY: run-local
run-local: build-local ## Build and run locally
	./patchwork start

.PHONY: container-build
container-build: ## Build a native OCI image with Podman
	$(CONTAINER_TOOL) build \
		$(CONTAINER_BUILD_ARGS) \
		--build-arg TARGETARCH=$(HOST_ARCH) \
		--tag $(FULL_IMAGE_NAME):$(IMAGE_TAG) \
		.

.PHONY: container-smoke
container-smoke: container-build ## Verify image metadata and the live health endpoint
	@name="patchwork-smoke-$$$$"; \
		$(CONTAINER_TOOL) run --detach --name "$$name" \
			--publish 127.0.0.1::8080 --env SECRET_KEY=container-smoke-test \
			$(FULL_IMAGE_NAME):$(IMAGE_TAG) >/dev/null; \
		trap '$(CONTAINER_TOOL) rm --force "$$name" >/dev/null 2>&1' EXIT; \
		port="$$( $(CONTAINER_TOOL) port "$$name" 8080/tcp | awk -F: 'NR == 1 {print $$NF}' )"; \
		for attempt in $$(seq 1 50); do \
			curl --fail --silent --show-error "http://127.0.0.1:$$port/healthz" && break; \
			test "$$attempt" -lt 50 || exit 1; \
			sleep 0.1; \
		done
	$(CONTAINER_TOOL) run --rm $(FULL_IMAGE_NAME):$(IMAGE_TAG) --version | grep -F "patchwork version $(VERSION)"

.PHONY: container-test
container-test: ## Run the race-enabled Go suite inside the build image
	$(CONTAINER_TOOL) build \
		$(CONTAINER_BUILD_ARGS) \
		--build-arg TARGETARCH=amd64 \
		--platform linux/amd64 \
		--target run-test \
		.

.PHONY: container-build-multiarch
container-build-multiarch: ## Build an amd64/arm64 OCI manifest with Podman
	@$(CONTAINER_TOOL) manifest exists $(MANIFEST_NAME) && \
		$(CONTAINER_TOOL) manifest rm $(MANIFEST_NAME) >/dev/null || true
	$(CONTAINER_TOOL) build $(CONTAINER_BUILD_ARGS) \
		--build-arg TARGETARCH=amd64 --platform linux/amd64 \
		--manifest $(MANIFEST_NAME) .
	$(CONTAINER_TOOL) build $(CONTAINER_BUILD_ARGS) \
		--build-arg TARGETARCH=arm64 --platform linux/arm64 \
		--manifest $(MANIFEST_NAME) .

.PHONY: container-push
container-push: container-build-multiarch ## Push the OCI manifest to the configured registry and tag
	$(CONTAINER_TOOL) manifest push --all \
		$(MANIFEST_NAME) \
		docker://$(FULL_IMAGE_NAME):$(IMAGE_TAG)

# Backward-compatible aliases for the project's former Docker targets.
.PHONY: build build-and-push test-docker release
build: container-build ## Build a native OCI image
build-and-push: container-push ## Build and push a multi-architecture OCI image
test-docker: container-test ## Run tests in the OCI build image
release: container-push ## Build and push a multi-architecture OCI image

.PHONY: build-amd64
build-amd64: ## Build an amd64 OCI image
	$(CONTAINER_TOOL) build $(CONTAINER_BUILD_ARGS) --build-arg TARGETARCH=amd64 \
		--platform linux/amd64 \
		--tag $(FULL_IMAGE_NAME):$(IMAGE_TAG)-amd64 .

.PHONY: build-arm64
build-arm64: ## Build an arm64 OCI image
	$(CONTAINER_TOOL) build $(CONTAINER_BUILD_ARGS) --build-arg TARGETARCH=arm64 \
		--platform linux/arm64 \
		--tag $(FULL_IMAGE_NAME):$(IMAGE_TAG)-arm64 .

.PHONY: build-ghcr
build-ghcr: ## Build and push to GitHub Container Registry
	$(MAKE) container-push REGISTRY=ghcr.io/tionis IMAGE_NAME=patchwork

.PHONY: build-dockerhub
build-dockerhub: ## Build and push to Docker Hub
	$(MAKE) container-push REGISTRY=tionis IMAGE_NAME=patchwork

.PHONY: clean
clean: ## Remove local build artifacts and the Patchwork manifest
	rm -f patchwork
	@$(CONTAINER_TOOL) manifest exists $(MANIFEST_NAME) && \
		$(CONTAINER_TOOL) manifest rm $(MANIFEST_NAME) >/dev/null || true

.PHONY: info
info: ## Show build and Podman information
	@echo "Image: $(FULL_IMAGE_NAME):$(IMAGE_TAG)"
	@echo "Platforms: $(PLATFORMS)"
	@echo "Container tool: $(CONTAINER_TOOL)"
	@$(CONTAINER_TOOL) version
