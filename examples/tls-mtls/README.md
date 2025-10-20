# TLS / mTLS Example

This example demonstrates configuring upstream TLS and mutual TLS for the gateway.

## Generate Test Certificates

You can create self-signed certificates for local testing:

```bash
cd examples/tls-mtls
./generate-certs.sh
```

This produces a CA, server, and client certificate inside `certs/`.

## Run the Gateway

Start the gateway with the TLS-aware configuration:

```bash
go run ./cmd/apigw run --config examples/tls-mtls/gateway.yaml
```

Point the trade/task upstream URLs at services that present the generated
certificates (or adjust the paths/insecure flag to match your environment).

## Highlights

- `trade` upstream requires full mTLS by presenting the CA and client cert/key.
- `task` upstream enables TLS but skips verification for scenarios where certs
  are managed externally.
- Useful as a starting point for production-grade TLS hardening.
