# Makefile for Patchwork - Multi-architecture Docker builds

# Variables
IMAGE_NAME ?= patchwork
IMAGE_TAG ?= latest
REGISTRY ?= ghcr.io/tionis
PLATFORMS ?= linux/amd64,linux/arm64
DOCKERFILE ?= Dockerfile
GO ?= go
GO_TEST_FLAGS ?= -mod=vendor -timeout=90s
COVERAGE_MIN ?= 70

# If REGISTRY is set, prepend it to the image name
ifdef REGISTRY
FULL_IMAGE_NAME = $(REGISTRY)/$(IMAGE_NAME)
else
FULL_IMAGE_NAME = $(IMAGE_NAME)
endif

# Default target
.PHONY: help
help: ## Show this help message
	@echo "Patchwork Docker Build Makefile"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Build targets
.PHONY: build
build: ## Build multi-architecture Docker images (amd64 and arm64)
	@echo "Building multi-architecture images for $(FULL_IMAGE_NAME):$(IMAGE_TAG)"
	docker buildx build \
		--platform $(PLATFORMS) \
		--tag $(FULL_IMAGE_NAME):$(IMAGE_TAG) \
		--file $(DOCKERFILE) \
		--load \
		.

.PHONY: build-and-push
build-and-push: ## Build and push multi-architecture Docker images
	@echo "Building and pushing multi-architecture images for $(FULL_IMAGE_NAME):$(IMAGE_TAG)"
	docker buildx build \
		--platform $(PLATFORMS) \
		--tag $(FULL_IMAGE_NAME):$(IMAGE_TAG) \
		--file $(DOCKERFILE) \
		--push \
		.

.PHONY: build-amd64
build-amd64: ## Build Docker image for amd64 only
	@echo "Building amd64 image for $(FULL_IMAGE_NAME):$(IMAGE_TAG)-amd64"
	docker buildx build \
		--platform linux/amd64 \
		--tag $(FULL_IMAGE_NAME):$(IMAGE_TAG)-amd64 \
		--file $(DOCKERFILE) \
		--load \
		.

.PHONY: build-arm64
build-arm64: ## Build Docker image for arm64 only
	@echo "Building arm64 image for $(FULL_IMAGE_NAME):$(IMAGE_TAG)-arm64"
	docker buildx build \
		--platform linux/arm64 \
		--tag $(FULL_IMAGE_NAME):$(IMAGE_TAG)-arm64 \
		--file $(DOCKERFILE) \
		--load \
		.

.PHONY: push-amd64
push-amd64: ## Build and push Docker image for amd64 only
	@echo "Building and pushing amd64 image for $(FULL_IMAGE_NAME):$(IMAGE_TAG)-amd64"
	docker buildx build \
		--platform linux/amd64 \
		--tag $(FULL_IMAGE_NAME):$(IMAGE_TAG)-amd64 \
		--file $(DOCKERFILE) \
		--push \
		.

.PHONY: push-arm64
push-arm64: ## Build and push Docker image for arm64 only
	@echo "Building and pushing arm64 image for $(FULL_IMAGE_NAME):$(IMAGE_TAG)-arm64"
	docker buildx build \
		--platform linux/arm64 \
		--tag $(FULL_IMAGE_NAME):$(IMAGE_TAG)-arm64 \
		--file $(DOCKERFILE) \
		--push \
		.

# Setup targets
.PHONY: setup-buildx
setup-buildx: ## Create and use a new buildx builder instance
	@echo "Setting up Docker buildx for multi-platform builds..."
	docker buildx create --name patchwork-builder --driver docker-container --bootstrap --use || true
	docker buildx inspect --bootstrap

.PHONY: remove-buildx
remove-buildx: ## Remove the buildx builder instance
	@echo "Removing Docker buildx builder..."
	docker buildx rm patchwork-builder || true

# Test targets
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
test-stress: ## Repeatedly stress the relay's concurrent state transitions
	$(GO) test $(GO_TEST_FLAGS) -race -shuffle=on -count=100 ./internal/relay

.PHONY: test-cover
test-cover: ## Enforce statement coverage and write coverage.out
	$(GO) test $(GO_TEST_FLAGS) -coverprofile=coverage.out ./...
	@total="$$( $(GO) tool cover -func=coverage.out | awk '/^total:/ {gsub("%", "", $$3); print $$3}' )"; \
		echo "Total coverage: $$total%"; \
		awk -v total="$$total" -v minimum="$(COVERAGE_MIN)" 'BEGIN { exit !(total >= minimum) }'

.PHONY: verify
verify: fmt-check vet test-race test-cover ## Run the complete local/CI verification suite

.PHONY: test-docker
test-docker: ## Run tests in Docker container
	@echo "Running tests in Docker container..."
	docker buildx build \
		--target run-test \
		--platform linux/amd64 \
		--file $(DOCKERFILE) \
		.

# Development targets
.PHONY: build-local
build-local: ## Build Go binary locally
	@echo "Building Go binary locally..."
	CGO_ENABLED=0 $(GO) build -mod=vendor -o patchwork .

.PHONY: run-local
run-local: build-local ## Build and run locally
	@echo "Running patchwork locally..."
	./patchwork start

.PHONY: clean
clean: ## Clean up local artifacts
	@echo "Cleaning up..."
	rm -f patchwork
	docker buildx prune -f

.PHONY: clean-all
clean-all: clean ## Clean up everything including Docker images
	@echo "Cleaning up Docker images..."
	docker images | grep $(IMAGE_NAME) | awk '{print $$3}' | xargs -r docker rmi -f

# Release targets
.PHONY: release
release: setup-buildx build-and-push ## Setup buildx and build/push multi-arch images

# Examples of usage with different registries:
.PHONY: build-ghcr
build-ghcr: ## Build and push to GitHub Container Registry
	$(MAKE) build-and-push REGISTRY=ghcr.io/tionis IMAGE_NAME=patchwork

.PHONY: build-dockerhub
build-dockerhub: ## Build and push to Docker Hub
	$(MAKE) build-and-push REGISTRY=tionis IMAGE_NAME=patchwork

# Info target
.PHONY: info
info: ## Show build information
	@echo "Build Information:"
	@echo "  Image Name: $(FULL_IMAGE_NAME)"
	@echo "  Tag: $(IMAGE_TAG)"
	@echo "  Platforms: $(PLATFORMS)"
	@echo "  Dockerfile: $(DOCKERFILE)"
	@echo ""
	@echo "Docker buildx info:"
	@docker buildx ls
