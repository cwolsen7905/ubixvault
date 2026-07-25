# syntax=docker/dockerfile:1

# --- build stage -----------------------------------------------------------
FROM golang:1.24-alpine AS build
WORKDIR /src

# Cache module downloads before copying the full tree.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# VERSION is stamped into the binary (matches the Makefile's -ldflags).
ARG VERSION=0.0.0-dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/ubixvault ./cmd/ubixvault

# --- runtime stage ---------------------------------------------------------
# distroless static + nonroot: no shell, no package manager, runs as uid 65532.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/ubixvault /usr/local/bin/ubixvault

USER 65532:65532
EXPOSE 8200
VOLUME ["/var/lib/ubixvault"]

ENTRYPOINT ["/usr/local/bin/ubixvault"]
# Bind all interfaces inside the container; TLS (or -dev-no-tls) is supplied by
# the deployment. The Helm chart overrides args as needed.
CMD ["server", "-listen", "0.0.0.0:8200", "-data", "/var/lib/ubixvault"]
