FROM --platform=linux/amd64 golang:1.27.0 AS build

ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
ARG TARGETARCH

WORKDIR /app
COPY go.mod go.sum ./
COPY ./vendor ./vendor
COPY ./*.go ./
COPY ./internal ./internal
COPY ./assets ./assets
RUN test -n "${TARGETARCH}" && \
  CGO_ENABLED=0 GOOS=linux GOARCH="${TARGETARCH}" go build -mod=vendor -trimpath \
  -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
  -o /patchwork
RUN mkdir -p /runtime && touch /runtime/.keep

# Run the tests in the container
FROM build AS run-test
RUN go test -mod=vendor -race -timeout=90s -shuffle=on ./...

FROM gcr.io/distroless/static-debian13:nonroot AS build-release-stage

ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

LABEL org.opencontainers.image.title="Patchwork" \
  org.opencontainers.image.description="A bounded-memory HTTP relay and webhook proxy" \
  org.opencontainers.image.source="https://github.com/tionis/patchwork" \
  org.opencontainers.image.version="${VERSION}" \
  org.opencontainers.image.revision="${COMMIT}" \
  org.opencontainers.image.created="${DATE}" \
  org.opencontainers.image.licenses="MIT"

COPY --from=build /patchwork /patchwork
COPY --from=build --chown=nonroot:nonroot /runtime/ /var/lib/patchwork/

WORKDIR /var/lib/patchwork

EXPOSE 8080

USER nonroot:nonroot

ENV LOG_LEVEL=info \
  PATCHWORK_DB_PATH=/var/lib/patchwork/patchwork.db
ENTRYPOINT ["/patchwork"]
CMD ["start"]
