# Microsoft Fabric Data Warehouse Connectivity & Authentication Proxy

A suite of Go and Java utilities for connecting to, proxying, and validating **Microsoft Fabric Data Warehouse** endpoints using **Microsoft Entra ID (Active Directory) Service Principal** authentication.

---

## Architecture Overview

Looker currently supports authenticating against Microsoft SQL Server databases primarily using traditional username/password credentials over TDS (Tabular Data Stream). Microsoft Fabric Data Warehouses require OAuth2 / Entra ID Service Principal authentication with mandatory TLS.

This repository provides three tools to bridge and validate this connection:

1. **`fabric-test`**: CLI tool to directly test and validate Entra ID Service Principal connectivity to Microsoft Fabric DW.
2. **`fabric-proxy`**: Lightweight, high-concurrency TDS protocol proxy that accepts standard SQL Server JDBC connections and translates them to Entra ID authenticated sessions on Fabric DW.
3. **`MockLookerClient`**: Test client utilizing the official Microsoft JDBC Driver (`mssql-jdbc`) to simulate Looker's connection patterns locally.

## Architecture diagram for fabric-proxy

```
┌─────────────────────────────────┐
│     Client (Looker / JDBC)      │
│  user: looker_user              │
│  pass: <proxy-password>         │
└────────────────┬────────────────┘
                 │ TDS (Plain TCP or TLS)
                 ▼
┌─────────────────────────────────┐
│          fabric-proxy           │  Authenticates incoming client credentials;
│          (Port 14330)           │  acquires Entra ID bearer token;
└────────────────┬────────────────┘  relays tabular SQL queries & results.
                 │                   TDS over TLS with Entra ID Bearer Token
                 ▼
┌─────────────────────────────────┐
│    Microsoft Fabric DW / Lake   │
│  (*.datawarehouse.fabric.       │
│    microsoft.com:1433)          │
└─────────────────────────────────┘
```

---

## Prerequisites & Fabric Configuration

Before using any of the tools, ensure your Azure and Fabric environments are configured:

1. **Fabric Tenant Setting:** In the Microsoft Fabric Admin Portal (`Tenant settings` -> `Developer settings`), enable **"Service principals can use Fabric APIs"** for the security group containing your Service Principal.
2. **Workspace Permissions:** Grant your Microsoft Entra Service Principal (Application ID) at least **Viewer** or **Contributor** access to the target Fabric Workspace.
3. **SQL Permissions:** Ensure the Service Principal has permissions to read the target warehouse (e.g. `GRANT CONNECT TO [<app-name>]`).

---

## Configuration Reference

All tools in this repository read configuration from environment variables or a local `.env` file. You can start by copying `.env.example`:

```bash
cp .env.example .env
```

| Environment Variable | CLI Flag | Default | Description |
| :--- | :--- | :--- | :--- |
| **`FABRIC_HOST`** | `-fabric-host` / `-host` | *Required* | Fabric DW endpoint (e.g. `xxx.datawarehouse.fabric.microsoft.com`) |
| **`FABRIC_PORT`** | `-fabric-port` / `-port` | `1433` | Fabric DW TDS port |
| **`FABRIC_DATABASE`** | `-fabric-database` / `-database` | *Required* | Fabric database / warehouse name |
| **`AZURE_TENANT_ID`** | `-tenant-id` | *Required* | Microsoft Entra Directory (Tenant) ID |
| **`AZURE_CLIENT_ID`** | `-client-id` | *Required* | Microsoft Entra Application (Client) ID |
| **`AZURE_CLIENT_SECRET`** | `-client-secret` | *Required* | Microsoft Entra Application Client Secret |
| **`FABRIC_TABLE`** | `-table` | `""` | Optional schema.table name for record count tests, for `fabric-test` only |
| **`PROXY_LISTEN_ADDR`** | `-listen` | `:14330` | Address and port for `fabric-proxy` to listen on |
| **`PROXY_USER`** | `-proxy-user` | `looker_user` | Incoming username expected by `fabric-proxy` |
| **`PROXY_PASSWORD`** | `-proxy-password` | *Required for proxy* | Incoming password expected by `fabric-proxy` |
| **`PROXY_LOG_LEVEL`** | `-log-level` | `info` | Logging verbosity: `info` or `debug` |
| **`PROXY_LOG_FORMAT`** | `-log-format` | `text` | Log format: `text` (human readable) or `json` (GCP Cloud Logging) |
| **`PROXY_SLOW_QUERY_MS`**| `-slow-query-ms` | `1000` | Latency threshold (ms) to trigger slow-query warnings |

---

## Tool 1: Connectivity Test Utility (`fabric-test`)

Directly verifies network connectivity, TLS handshake, Entra ID token acquisition, and query execution against Microsoft Fabric DW.

### Running with Go

```bash
# Using parameters from .env
go run ./cmd/fabric-test

# Or passing flags explicitly
go run ./cmd/fabric-test \
  -host "xxx.datawarehouse.fabric.microsoft.com" \
  -database "my_warehouse" \
  -client-id "00000000-0000-0000-0000-000000000000" \
  -tenant-id "00000000-0000-0000-0000-000000000000" \
  -client-secret "your-secret" \
  -table "dbo.orders"
```

### Building and Running the Binary

```bash
go build -o fabric-test ./cmd/fabric-test
./fabric-test
```

### Execution Steps & Output
1. Validates configuration and verifies Entra ID credentials.
2. Connects to Fabric DW over TLS using `fedauth=ActiveDirectoryServicePrincipal`.
3. Queries server version (`SELECT 1, @@VERSION`).
4. Executes `SELECT COUNT(*) FROM <table>` (if `-table` is provided).
5. Outputs connection and execution latency metrics.

---

## Tool 2: Fabric Authentication Proxy (`fabric-proxy`)

A high-performance daemon that intercepts incoming TDS connections from legacy JDBC/ODBC clients, verifies client credentials, dials Microsoft Fabric DW using Entra ID Service Principal authentication, and streams tabular queries and results bidirectionally.

### Key Capabilities
- **TDS Handshake & Encryption:** Supports both unencrypted local connections (`encryptNotSup`) and TLS handshakes using dynamically generated in-memory certificates.
- **Authentication Bridge:** Translates incoming plain username/password logins into Entra ID OAuth tokens.
- **Literal Query Streaming:** Direct L7 streaming of `packSQLBatch` packets with real-time response forwarding.
- **Query Performance Tracking:** Tracks roundtrip latency for each SQL batch and flags slow queries.

### Running Locally

```bash
# Build the binary
go build -o fabric-proxy ./cmd/fabric-proxy

# Run the proxy
./fabric-proxy
```

### Client Configuration (Looker / Generic JDBC)

Configure the database connection in Looker or your JDBC client using the following settings:

- **Dialect:** Microsoft SQL Server (2012+)
- **Host:** IP or hostname of the proxy server (e.g. `localhost` or private VM IP)
- **Port:** `14330` (or configured `PROXY_LISTEN_ADDR`)
- **Database:** Target Fabric warehouse name
- **Username:** Value of `PROXY_USER` (e.g. `looker_user`)
- **Password:** Value of `PROXY_PASSWORD`
- **Additional JDBC Parameters:**
  ```text
  encrypt=false;trustServerCertificate=true
  ```
  *(Or if using TLS to the proxy: `encrypt=true;trustServerCertificate=true`)*

**JDBC Connection URL:**
```text
jdbc:sqlserver://localhost:14330;databaseName=your_warehouse;user=looker_user;password=your_password;encrypt=false;trustServerCertificate=true
```

### Observability & Logging

#### Log Formats (`PROXY_LOG_FORMAT`)
- **`text` (Default):** Human-readable output formatted for terminal and systemd journals.
  ```text
  2026-09-30 07:20:01 [INFO ] [10.10.0.5:54321] Authenticated user 'looker_user' (Looker). Connecting upstream to Fabric DW...
  2026-09-30 07:20:02 [QUERY] [10.10.0.5:54321] [34.2ms] SELECT count(*) FROM orders
  2026-09-30 07:20:05 [WARN ] [10.10.0.5:54321] [SLOW 2450.1ms] SELECT * FROM lineitem WHERE l_shipdate <= '1998-12-01'
  2026-09-30 07:20:10 [INFO ] [10.10.0.5:54321] Session ended: duration=10.2s, queries=4, rx=1240 bytes, tx=48920 bytes (graceful close)
  ```
- **`json`:** Emits structured JSON compatible with Google Cloud Logging. Logs include `severity`, `time`, `client`, `query`, `duration_ms`, and `slow_query` fields for log filtering in GCP Cloud Logging.

#### Dynamic Per-Connection Debug Toggle
Debug logging can be enabled globally via `PROXY_LOG_LEVEL=debug` or dynamically on a per-connection basis without restarting the proxy:

1. **Via `applicationName` parameter:** Add `applicationName=Looker-debug;` to the JDBC connection string.
2. **Via `username` parameter:** Connect with `username=looker_user#debug` (the proxy strips the `#debug` suffix and enables verbose packet tracing for that session).
3. **Via `databaseName` parameter:** Set database to `your_db;debug=true`.

---

## Production Deployment Options

Because Microsoft SQL Server TDS is a stateful binary TCP protocol, deployment on Google Compute Engine (GCE), Google Kubernetes Engine (GKE), or any host supporting TCP listeners is recommended. (Cloud Run does not support the necessary raw TCP capabilities.) 

### Option A: Container Deployment (Docker / Container-Optimized OS)

The included multi-stage [`Dockerfile`](./Dockerfile) produces a minimal static runtime image (~15MB):

```bash
# Build container image
docker build -t fabric-proxy:latest .

# Run container with environment file
docker run -d \
  --name=fabric-proxy \
  --restart=always \
  --net=host \
  --env-file=.env \
  fabric-proxy:latest
```

### Option B: Systemd Daemon on Linux VM

Use the provided [`fabric-proxy.service`](./fabric-proxy.service) unit file:

```bash
# 1. Copy binary and configuration to target host
sudo mkdir -p /opt/fabric-proxy
sudo cp fabric-proxy /opt/fabric-proxy/
sudo cp .env /opt/fabric-proxy/
sudo cp fabric-proxy.service /etc/systemd/system/

# 2. Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable --now fabric-proxy

# 3. View live logs
journalctl -u fabric-proxy -f
```

---

## Tool 3: Mock Looker JDBC Client (`MockLookerClient`)

A Java-based test utility that loads the **official Microsoft SQL Server JDBC Driver** (`mssql-jdbc`) to simulate Looker's connection lifecycle against the proxy.

### Purpose
- Verifies that `fabric-proxy` correctly negotiates TDS handshakes and authenticates with standard JDBC drivers.
- Validates metadata introspection queries (`getDatabaseProductName()`, `getDatabaseProductVersion()`).
- Tests SQL queries without requiring a live Looker deployment.

### Running the Mock Client

Ensure Java (JDK 11+) is available. A helper script [`scripts/test-mock-looker.sh`](./scripts/test-mock-looker.sh) handles driver download, compilation, and execution:

```bash
# Standard test (reads credentials from .env)
./scripts/test-mock-looker.sh

# Test with dynamic debug logging enabled
./scripts/test-mock-looker.sh --debug

# Test with client-to-proxy TLS encryption enabled
./scripts/test-mock-looker.sh --encrypt
```

### Sample Output

```text
================================================================
  Mock Looker JDBC Client (Official Microsoft JDBC Driver)
================================================================

[1/4] Connecting via JDBC:
      URL: jdbc:sqlserver://localhost:14330;databaseName=looker-test-wh;user=looker_user;password=********;encrypt=false;trustServerCertificate=true;applicationName=Looker;
      Client Application Name: Looker
      TLS Encryption to Proxy: Disabled (Plain TCP)
[2/4] Successfully connected to proxy in 648 ms!

[3/4] Connection Metadata (from Fabric DW via Proxy):
      Database Product: Microsoft SQL Azure
      Database Version: 12.0.2000.8
      Driver Name:      Microsoft JDBC Driver 12.8 for SQL Server
      Driver Version:   12.8.1.0

[4/4] Executing Looker-style literal SQL queries...

--- Executing SQL: SELECT 1 AS looker_test_val, 'Fabric Proxy Connected' AS status;
    looker_test_val | status
    ------------------------
    1 | Fabric Proxy Connected
    (1 row(s) returned in 24 ms)

================================================================
  All Mock Looker queries executed successfully!
================================================================
```

---

## Repository Structure

```text
├── cmd/
│   ├── fabric-proxy/
│   │   └── main.go                 # TDS proxy daemon source code
│   └── fabric-test/
│       └── main.go                 # Fabric connectivity test utility
├── scripts/
│   └── test-mock-looker.sh         # Mock Looker test runner script
├── test/
│   └── MockLookerClient.java       # Mock Looker JDBC client using mssql-jdbc
├── .dockerignore                   # Build context exclusions
├── .env.example                    # Configuration template
├── .gcloudignore                   # Cloud Build upload exclusions
├── .gitignore                      # Git ignored files (binaries, secrets, jars)
├── Dockerfile                      # Multi-stage production container build
├── fabric-proxy.service            # Systemd service unit file
├── go.mod                          # Go module dependencies
├── go.sum                          # Go checksums
└── README.md                       # Documentation
```
