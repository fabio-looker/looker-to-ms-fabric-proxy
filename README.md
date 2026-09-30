# Microsoft Fabric DW Connectivity & Auth Proxy (Go POC)

This repository contains a proof-of-concept connectivity test script written in Go for validating connections to a **Microsoft Fabric Data Warehouse** using **Microsoft Entra ID (Active Directory) Service Principal** authentication.

---

## 1. Is Go a Suitable Language for this?

**Yes — in fact, Go is arguably one of the best languages for this use case.**

### A. Direct Fabric DW Connectivity
- Microsoft Fabric Data Warehouses and Lakehouses expose a standard **TDS (Tabular Data Stream)** protocol endpoint over port 1433 with mandatory TLS.
- Microsoft actively maintains the official Go TDS driver: [`github.com/microsoft/go-mssqldb`](https://github.com/microsoft/go-mssqldb), which includes dedicated Azure AD / Entra ID support via its [`azuread`](https://pkg.go.dev/github.com/microsoft/go-mssqldb/azuread) package.
- It supports `ActiveDirectoryServicePrincipal` natively, generating Entra ID access tokens for the database resource (`https://database.windows.net/.default`).

### B. High-Concurrency Authentication Proxy
For an authentication proxy sitting in front of Fabric DW, Go offers significant architectural advantages over alternatives (Python, Node.js, or Java):

1. **Massive Concurrency & Low Footprint:**
   - Go's lightweight **goroutines** start with ~2KB memory overhead (compared to ~1MB per OS thread in traditional runtimes).
   - A single Go process can effortlessly sustain tens of thousands of concurrent client connections with predictable latency and low garbage collection overhead.
2. **Token Caching & Entra Throttling Protection:**
   - In high-concurrency workloads, obtaining a fresh OAuth token from Entra ID per connection or query will rapidly hit Entra ID rate limits.
   - Using Go's [`golang.org/x/sync/singleflight`](https://pkg.go.dev/golang.org/x/sync/singleflight) and an in-memory token cache (with proactive background refresh at ~80% of TTL), thousands of concurrent incoming requests can reuse a single cached bearer token safely without race conditions or stampeding stampedes.
3. **TDS Protocol Handling / Network Proxying:**
   - Go's standard `net` package and `io.Copy` / `net.Conn` primitives make building TCP proxies or L7 TDS protocol interceptors straightforward and high-throughput.
4. **Single Static Binary:**
   - Deploys as a self-contained, statically linked binary with zero external runtime dependencies. Ideal for small container images (scratch/distroless), Kubernetes sidecars, or daemon services.

---

## 2. Prerequisites for Microsoft Fabric

To allow a Service Principal to connect to a Fabric Data Warehouse:
1. **Fabric Tenant Setting:** In the Fabric Admin Portal -> *Tenant settings* -> *Developer settings*, ensure **"Service principals can use Fabric APIs"** is enabled for the security group containing your Service Principal.
2. **Workspace Access:** Add the Service Principal (App Registration) as a **Member**, **Contributor**, or **Viewer** to the Fabric Workspace containing your warehouse.
3. **Warehouse Permissions:** If not an admin/contributor, grant SQL permissions (e.g. `GRANT CONNECT TO [<service-principal-name>]` or `GRANT SELECT ON SCHEMA::dbo TO ...`).

---

## 3. Running the Connectivity Test Script

### Option A: Using Command-Line Flags

```bash
go run main.go \
  -host "<workspace-guid>.datawarehouse.fabric.microsoft.com" \
  -port 1433 \
  -database "<warehouse-name>" \
  -client-id "<azure-client-id>" \
  -tenant-id "<azure-tenant-id>" \
  -client-secret "<azure-client-secret>" \
  [-table "dbo.my_table"]
```

### Option B: Using Environment Variables

You can copy `.env.example` or export the variables:

```bash
cp .env.example .env
# Edit .env with your credentials
source .env

go run main.go
```

Or run the precompiled binary:

```bash
./fabric-test
```

### Script Behavior
1. Validates all required connection parameters.
2. Builds the secure TDS connection string with `fedauth=ActiveDirectoryServicePrincipal` and TLS encryption enforced.
3. Pings the database to verify the TLS handshake and Entra ID Service Principal token exchange.
4. Executes the test query:
   - If `-table` is provided: runs `SELECT COUNT(*) FROM <table>` and reports the record count.
   - If `-table` is omitted: runs `SELECT 1, @@VERSION` and outputs the server version.
5. Measures and prints the duration for connection establishment and query execution.

---

## 4. Authentication Proxy for Looker / Legacy JDBC (`fabric-proxy`)

Legacy business intelligence tools like **Looker** often only support standard SQL Server username + password authentication through standard JDBC drivers (`mssql-jdbc` or `jTDS`), and do not natively support Microsoft Entra ID (Active Directory) Service Principal tokens. Furthermore, Looker issues literal SQL text queries (`Statement.executeQuery`) rather than parameterized prepared statements.

`fabric-proxy` is a specialized TDS (Tabular Data Stream) authentication proxy designed specifically for this architecture:

```
 ┌─────────────────┐       TDS (Plain/TLS)       ┌──────────────────┐      TDS (TLS + Entra ID)     ┌───────────────────────┐
 │     Looker      │ ──────────────────────────> │   fabric-proxy   │ ────────────────────────────> │  Microsoft Fabric DW  │
 │  (Legacy JDBC)  │  user: looker_user          │  (Go Proxy on    │  Service Principal Bearer Token│ (Entra Authenticated) │
 │                 │  pass: looker_secret        │   port :14330)   │  clientID@tenantID + secret   │                       │
 └─────────────────┘                             └──────────────────┘                               └───────────────────────┘
```

### How It Works:
1. **Accepts Incoming JDBC Connections:** Listens on a local port (e.g. `:14330`).
2. **Negotiates TDS Handshake:** Handles client `PRELOGIN` requests (supports both unencrypted local connections and TLS with dynamically generated certificates).
3. **Authenticates Client:** Intercepts and parses the TDS `LOGIN7` packet to validate Looker's incoming username and password against `PROXY_USER` and `PROXY_PASSWORD`. Mismatched credentials receive standard TDS `18456` login failure errors.
4. **Bridges to Microsoft Fabric:** On successful authentication, dials Fabric DW using Microsoft Entra ID Service Principal authentication via `go-mssqldb/azuread`.
5. **Transparent Query Relaying & Logging:** Transmits literal SQL batches directly between Looker and Fabric DW, streaming tabular query results back in real time while logging executed queries for auditability.

### Running the Proxy:

Add the incoming credentials to your `.env` file:
```bash
PROXY_LISTEN_ADDR=":14330"
PROXY_USER="looker_user"
PROXY_PASSWORD="looker_secret_password"
```

Run the proxy using Go:
```bash
go run cmd/fabric-proxy/main.go
```

Or run the compiled binary:
```bash
./fabric-proxy
```

### Configuring Looker (JDBC Connection Settings):

In the Looker Database Connection admin console:

- **Dialect:** Microsoft SQL Server (2012+)
- **Host:** `localhost` (or the IP / hostname where `fabric-proxy` is deployed)
- **Port:** `14330`
- **Database:** Your Fabric warehouse name (e.g. `looker-test-wh`)
- **Username:** Value of `PROXY_USER` (e.g. `looker_user`)
- **Password:** Value of `PROXY_PASSWORD` (e.g. `looker_secret_password`)
- **Additional JDBC Parameters:**
  ```text
  encrypt=false;trustServerCertificate=true
  ```
  *(Or if using TLS to the proxy: `encrypt=true;trustServerCertificate=true`)*

Full equivalent JDBC URL:
```text
jdbc:sqlserver://localhost:14330;databaseName=your_warehouse;user=looker_user;password=looker_secret_password;encrypt=false;trustServerCertificate=true
```

---

## 5. Observability & Logging Insights

The proxy provides operational metrics for monitoring, query performance analysis, and debugging.

### A. Google Cloud Logging & Format Toggle
Configure `PROXY_LOG_FORMAT` in `.env`:
- **`text` (Default for local CLI & systemd journal):**
  ```text
  2026-09-29 20:55:00 [INFO ] [10.128.0.5:54321] Authenticated user 'looker_user' (Looker). Connecting upstream to Fabric DW...
  2026-09-29 20:55:01 [QUERY] [10.128.0.5:54321] [34.2ms] SELECT count(*) FROM orders
  2026-09-29 20:55:05 [WARN ] [10.128.0.5:54321] [SLOW 2450.1ms] SELECT * FROM lineitem WHERE l_shipdate <= '1998-12-01'
  2026-09-29 20:55:10 [INFO ] [10.128.0.5:54321] Session ended: duration=10.2s, queries=4, rx=1240 bytes, tx=48920 bytes (graceful close)
  ```
- **`json` (Recommended for GCP / Cloud Logging):**
  Emits structured JSON payload lines containing `severity`, `time`, `client`, `query`, `duration_ms`, `slow_query`, and metadata. Google Cloud Logging automatically parses these fields, allowing filtering by `jsonPayload.duration_ms > 1000` or `jsonPayload.client`.

### B. Dual-Level Debug Toggles

You can enable debug logging at the server level or dynamically on a per-connection basis:

1. **Global Server Toggle:**
   Set `PROXY_LOG_LEVEL="debug"` in `.env` (or pass `-log-level=debug`).

2. **Dynamic Per-Connection Toggle (Zero Restart):**
   Any client (e.g. Looker) can dynamically activate debug logs for its connection by including `debug` in its connection parameters:
   - **Via `applicationName`:** In Looker's Additional JDBC Parameters:
     `applicationName=Looker-debug;encrypt=false;trustServerCertificate=true`
   - **Via `username`:** Set Looker username to `looker_user#debug` (the proxy strips the `#debug` tag and authenticates against `PROXY_USER`, but marks the connection for debug logging).
   - **Via `databaseName`:** Set database to `looker-test-wh;debug=true`.

When debug is enabled, detailed TDS packet traces, client workstation names, and Entra ID token roundtrip timings are logged.

### C. Slow Query Detection
Set `PROXY_SLOW_QUERY_MS=1000` (default 1000ms). Any query whose execution on Fabric DW exceeds this threshold is flagged with `WARNING` severity.

---

## 6. Deployment on Google Compute Engine (GCE)

Because SQL Server TDS is a stateful binary TCP protocol (not HTTP), deploying to a **Google Compute Engine (GCE)** VM or GKE is the recommended pattern on Google Cloud. A micro/small VM (`e2-micro` or `e2-small`) easily handles high concurrency with sub-millisecond overhead.

### Option A: Direct VM Deployment with Systemd

1. Create an `e2-micro` or `e2-small` Debian/Ubuntu VM on GCE:
   ```bash
   gcloud compute instances create fabric-proxy-vm \
       --zone=us-central1-a \
       --machine-type=e2-small \
       --tags=fabric-proxy
   ```
2. Allow incoming traffic on port 14330 from your Looker instance / VPC:
   ```bash
   gcloud compute firewall-rules create allow-fabric-proxy \
       --allow=tcp:14330 \
       --target-tags=fabric-proxy \
       --source-ranges=<LOOKER_IP_OR_VPC_CIDR>
   ```
3. Copy `fabric-proxy`, `.env`, and `fabric-proxy.service` to the VM:
   ```bash
   ssh fabric-proxy-vm "sudo mkdir -p /opt/fabric-proxy"
   scp fabric-proxy .env fabric-proxy-vm:/opt/fabric-proxy/
   scp fabric-proxy.service fabric-proxy-vm:/etc/systemd/system/
   ```
4. Enable and start the systemd service:
   ```bash
   ssh fabric-proxy-vm "sudo systemctl daemon-reload && sudo systemctl enable --now fabric-proxy"
   ```
5. View live logs:
   ```bash
   ssh fabric-proxy-vm "journalctl -u fabric-proxy -f"
   ```

### Option B: Docker Container Deployment (Container-Optimized OS)

1. Build and push the container image to Google Artifact Registry:
   ```bash
   docker build -t us-central1-docker.pkg.dev/<PROJECT_ID>/images/fabric-proxy:latest .
   docker push us-central1-docker.pkg.dev/<PROJECT_ID>/images/fabric-proxy:latest
   ```
2. Run on GCE Container-Optimized OS:
   ```bash
   gcloud compute instances create-with-container fabric-proxy-cos \
       --zone=us-central1-a \
       --machine-type=e2-small \
       --container-image=us-central1-docker.pkg.dev/<PROJECT_ID>/images/fabric-proxy:latest \
       --container-env-file=.env \
       --tags=fabric-proxy
   ```
