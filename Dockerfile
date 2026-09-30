# syntax=docker/dockerfile:1

# Stage 1: Build the static Go binary
FROM golang:1.26-alpine AS builder

WORKDIR /app

# Install git and CA certificates
RUN apk add --no-cache git ca-certificates tzdata

# Cache module dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code and compile
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w" \
    -o /fabric-proxy ./cmd/fabric-proxy

# Stage 2: Minimal runtime container
FROM alpine:3.20

WORKDIR /

# Include trusted root CA certificates for Azure AD / Entra ID and Fabric TLS
RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /fabric-proxy /fabric-proxy

# Default TDS proxy port
EXPOSE 14330

ENTRYPOINT ["/fabric-proxy"]
