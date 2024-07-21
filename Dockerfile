FROM golang:1.22.5 AS build
WORKDIR /app
COPY go.mod go.sum ./
COPY ./vendor ./vendor
COPY ./*.go ./
COPY ./huproxy ./huproxy/
COPY ./assets ./assets
RUN CGO_ENABLED=0 GOOS=linux go build -o /patchwork

# Run the tests in the container
FROM build AS run-test
RUN go test -v ./...

FROM gcr.io/distroless/base-debian11 AS build-release-stage

WORKDIR /

COPY --from=build /patchwork /patchwork

EXPOSE 8080

USER nonroot:nonroot

ENV LOG_LEVEL=info
ENTRYPOINT ["/patchwork"]
