# syntax=docker/dockerfile:1

FROM golang:1.22-alpine AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg
COPY openapi-merge.config.json ./
COPY specs ./specs

RUN CGO_ENABLED=0 GOOS=linux go build -o /out/gateway ./cmd/gateway
RUN mkdir -p /app/dist && chmod 0777 /app/dist

FROM gcr.io/distroless/base-debian12
WORKDIR /app

COPY --from=builder /out/gateway /usr/local/bin/gateway
COPY --from=builder /app/openapi-merge.config.json ./openapi-merge.config.json
COPY --from=builder /app/specs ./specs
COPY --from=builder /app/dist ./dist

ENV PORT=8080
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/gateway"]
