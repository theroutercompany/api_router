# syntax=docker/dockerfile:1

# Build stage: compile the apigw binary.
FROM golang:1.23-alpine AS builder
WORKDIR /app

ENV GOTOOLCHAIN=auto

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg
COPY openapi-merge.config.json ./
COPY specs ./specs

RUN CGO_ENABLED=0 GOOS=linux go build -o /tmp/apigw ./cmd/gateway

# Runtime stage: minimal distroless image.
FROM gcr.io/distroless/base-debian12
WORKDIR /app

COPY --from=builder /tmp/apigw /usr/local/bin/apigw
COPY --from=builder /app/openapi-merge.config.json ./openapi-merge.config.json
COPY --from=builder /app/specs ./specs

ENV PORT=8080
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/apigw"]
