# syntax=docker/dockerfile:1

# --- builder: compile a static binary -------------------------------------
FROM golang:1.26 AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=docker
# CGO_ENABLED=0 ⇒ a fully static binary that runs on distroless/static.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/darbaan ./cmd/darbaan

# Pre-create the data dir owned by the nonroot uid (65532) so a fresh named
# volume mounted at /data inherits writable ownership — distroless has no shell
# to chown at runtime.
RUN mkdir -p /data && chown 65532:65532 /data

# --- runtime: minimal, non-root -------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/darbaan /usr/local/bin/darbaan
COPY --from=builder --chown=65532:65532 /data /data

# Env-driven config (file < env < flags). Point the three bbolt DBs at the
# /data volume and keep the safe default sender-type=stub: a fresh container
# sends NOTHING until the operator sets sender-type=smtp + the app password.
# Secrets (DARBAAN_AGENT_PASS, DARBAAN_SMTP_PASSWORD) and files (DKIM key, TLS
# certs, optional config) come from env / mounts — never baked into the image.
ENV DARBAAN_SLUICE_DB=/data/sluice.db \
    DARBAAN_AUDIT_DB=/data/audit.db \
    DARBAAN_INBOUND_DB=/data/inbound.db \
    DARBAAN_SENDER_TYPE=stub

# SMTP submission face + IMAP read face.
EXPOSE 1465 1143

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/darbaan"]
CMD ["serve"]
