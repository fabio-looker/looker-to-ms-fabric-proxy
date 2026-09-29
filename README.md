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
