FROM golang:1.22.1 AS builder
WORKDIR /app
COPY .. /app
RUN CGO_ENABLED=1 GOOS=linux go build -o /app/patchwork
CMD ["/app/patchwork"]
