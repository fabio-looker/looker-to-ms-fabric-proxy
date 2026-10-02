package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/microsoft/go-mssqldb/azuread"
)

type Config struct {
	Host         string
	Port         int
	Database     string
	ClientID     string
	TenantID     string
	ClientSecret string
	Table        string
	Timeout      time.Duration
}

func loadEnvFile(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	loadedCount := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		if len(val) >= 2 && ((val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'')) {
			val = val[1 : len(val)-1]
		}
		if _, exists := os.LookupEnv(key); !exists {
			os.Setenv(key, val)
			loadedCount++
		}
	}
	if loadedCount > 0 {
		fmt.Printf("[INFO] Loaded %d configuration variables from %s\n", loadedCount, path)
	}
}

func getEnvOrDefault(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return strings.TrimSpace(val)
	}
	return fallback
}

func parseFlags() (*Config, error) {
	loadEnvFile(".env")

	cfg := &Config{}

	portDefault := 1433
	if envPort := os.Getenv("FABRIC_PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil {
			portDefault = p
		}
	}

	flag.StringVar(&cfg.Host, "host", getEnvOrDefault("FABRIC_HOST", ""), "Fabric DW host endpoint (e.g., xxx.datawarehouse.fabric.microsoft.com)")
	flag.IntVar(&cfg.Port, "port", portDefault, "Port number (default 1433)")
	flag.StringVar(&cfg.Database, "database", getEnvOrDefault("FABRIC_DATABASE", ""), "Fabric DW database/warehouse name")
	flag.StringVar(&cfg.ClientID, "client-id", getEnvOrDefault("AZURE_CLIENT_ID", ""), "Entra Application (Client) ID")
	flag.StringVar(&cfg.TenantID, "tenant-id", getEnvOrDefault("AZURE_TENANT_ID", ""), "Entra Directory (Tenant) ID")
	flag.StringVar(&cfg.ClientSecret, "client-secret", "", "Entra Application (Client) Secret (defaults to AZURE_CLIENT_SECRET env var)")
	flag.StringVar(&cfg.Table, "table", getEnvOrDefault("FABRIC_TABLE", ""), "Optional table name for SELECT COUNT(*) test")

	timeoutSec := flag.Int("timeout", 30, "Connection and query timeout in seconds")

	flag.Parse()

	if cfg.ClientSecret == "" {
		cfg.ClientSecret = os.Getenv("AZURE_CLIENT_SECRET")
	}

	cfg.Timeout = time.Duration(*timeoutSec) * time.Second

	var missing []string
	if cfg.Host == "" {
		missing = append(missing, "-host or FABRIC_HOST")
	}
	if cfg.Database == "" {
		missing = append(missing, "-database or FABRIC_DATABASE")
	}
	if cfg.ClientID == "" {
		missing = append(missing, "-client-id or AZURE_CLIENT_ID")
	}
	if cfg.TenantID == "" {
		missing = append(missing, "-tenant-id or AZURE_TENANT_ID")
	}
	if cfg.ClientSecret == "" {
		missing = append(missing, "-client-secret or AZURE_CLIENT_SECRET")
	}

	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required configuration parameters:\n  - %s", strings.Join(missing, "\n  - "))
	}

	return cfg, nil
}

func buildConnectionString(cfg *Config) string {
	// go-mssqldb/azuread format:
	// For ActiveDirectoryServicePrincipal, user id is clientID@tenantID, and password is clientSecret.
	// We build a standard URL DSN:
	// sqlserver://clientID%40tenantID:clientSecret@host:port?database=...&fedauth=ActiveDirectoryServicePrincipal
	query := url.Values{}
	query.Add("database", cfg.Database)
	query.Add("fedauth", "ActiveDirectoryServicePrincipal")
	query.Add("encrypt", "true")
	query.Add("TrustServerCertificate", "false")

	// Microsoft Entra SP user is clientID@tenantID
	username := fmt.Sprintf("%s@%s", cfg.ClientID, cfg.TenantID)

	u := &url.URL{
		Scheme:   "sqlserver",
		User:     url.UserPassword(username, cfg.ClientSecret),
		Host:     fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		RawQuery: query.Encode(),
	}

	return u.String()
}

func main() {
	cfg, err := parseFlags()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n\n", err)
		fmt.Fprintf(os.Stderr, "Usage example:\n")
		fmt.Fprintf(os.Stderr, "  go run main.go \\\n")
		fmt.Fprintf(os.Stderr, "    -host \"<workspace-id>.datawarehouse.fabric.microsoft.com\" \\\n")
		fmt.Fprintf(os.Stderr, "    -database \"<warehouse_name>\" \\\n")
		fmt.Fprintf(os.Stderr, "    -client-id \"<application_id>\" \\\n")
		fmt.Fprintf(os.Stderr, "    -tenant-id \"<directory_id>\" \\\n")
		fmt.Fprintf(os.Stderr, "    -client-secret \"<secret>\" \\\n")
		fmt.Fprintf(os.Stderr, "    [-table \"<schema.table>\"]\n")
		os.Exit(1)
	}

	dsn := buildConnectionString(cfg)

	fmt.Println("==================================================")
	fmt.Println("Microsoft Fabric DW Connectivity Verification")
	fmt.Println("==================================================")
	fmt.Printf("Host:        %s:%d\n", cfg.Host, cfg.Port)
	fmt.Printf("Database:    %s\n", cfg.Database)
	fmt.Printf("Client ID:   %s\n", cfg.ClientID)
	fmt.Printf("Tenant ID:   %s\n", cfg.TenantID)
	fmt.Println("Auth Method: ActiveDirectoryServicePrincipal")
	if cfg.Table != "" {
		fmt.Printf("Test Table:  %s\n", cfg.Table)
	} else {
		fmt.Printf("Test Query:  SELECT 1\n")
	}
	fmt.Println("--------------------------------------------------")

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	fmt.Print("Connecting to database... ")
	startTime := time.Now()

	// Driver "azuresql" is registered by github.com/microsoft/go-mssqldb/azuread
	db, err := sql.Open("azuresql", dsn)
	if err != nil {
		fmt.Printf("FAILED\n")
		fmt.Fprintf(os.Stderr, "Error creating connection pool: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Ping database to establish the connection and verify authentication
	if err := db.PingContext(ctx); err != nil {
		fmt.Printf("FAILED (elapsed: %v)\n", time.Since(startTime).Round(time.Millisecond))
		fmt.Fprintf(os.Stderr, "\nConnection/Authentication Error: %v\n", err)
		printTroubleshootingTips(err)
		os.Exit(1)
	}
	connectDuration := time.Since(startTime).Round(time.Millisecond)
	fmt.Printf("SUCCESS (%v)\n", connectDuration)

	// Execute test query
	if cfg.Table != "" {
		// Caution: validate or quote table name to prevent SQL syntax injection
		query := fmt.Sprintf("SELECT COUNT(*) FROM %s", sanitizeIdentifier(cfg.Table))
		fmt.Printf("Executing query: %s... ", query)

		queryStart := time.Now()
		var count int64
		err = db.QueryRowContext(ctx, query).Scan(&count)
		if err != nil {
			fmt.Printf("FAILED (elapsed: %v)\n", time.Since(queryStart).Round(time.Millisecond))
			fmt.Fprintf(os.Stderr, "Query execution error: %v\n", err)
			os.Exit(1)
		}
		queryDuration := time.Since(queryStart).Round(time.Millisecond)
		fmt.Printf("SUCCESS (%v)\n", queryDuration)
		fmt.Printf("Result row count: %d\n", count)
	} else {
		query := "SELECT 1, @@VERSION"
		fmt.Printf("Executing query: %s... ", query)

		queryStart := time.Now()
		var val int
		var version string
		err = db.QueryRowContext(ctx, query).Scan(&val, &version)
		if err != nil {
			fmt.Printf("FAILED (elapsed: %v)\n", time.Since(queryStart).Round(time.Millisecond))
			fmt.Fprintf(os.Stderr, "Query execution error: %v\n", err)
			os.Exit(1)
		}
		queryDuration := time.Since(queryStart).Round(time.Millisecond)
		fmt.Printf("SUCCESS (%v)\n", queryDuration)
		fmt.Printf("Ping response: %d\n", val)
		firstLineVersion := strings.Split(version, "\n")[0]
		fmt.Printf("Server version: %s\n", strings.TrimSpace(firstLineVersion))
	}

	fmt.Println("==================================================")
	fmt.Println("Status: Connectivity and authentication succeeded!")
	fmt.Println("==================================================")
}

func sanitizeIdentifier(tbl string) string {
	// If already brackets or quotes are provided, return as is
	tbl = strings.TrimSpace(tbl)
	if strings.Contains(tbl, "[") || strings.Contains(tbl, "\"") {
		return tbl
	}
	parts := strings.Split(tbl, ".")
	for i, p := range parts {
		parts[i] = "[" + strings.TrimSpace(p) + "]"
	}
	return strings.Join(parts, ".")
}

func printTroubleshootingTips(err error) {
	fmt.Fprintln(os.Stderr, "\nTroubleshooting Tips for Microsoft Fabric DW:")
	msg := err.Error()

	if strings.Contains(msg, "Login failed") || strings.Contains(msg, "AADSTS") || strings.Contains(msg, "authentication") {
		fmt.Fprintln(os.Stderr, "1. Ensure the Service Principal (App ID) has been granted access to the Fabric Workspace:")
		fmt.Fprintln(os.Stderr, "   - Add the App ID as a Member/Contributor/Viewer in the Fabric Workspace.")
		fmt.Fprintln(os.Stderr, "   - Or grant SELECT permissions in the SQL endpoint / warehouse.")
		fmt.Fprintln(os.Stderr, "2. Ensure Fabric Tenant Settings allow Service Principals:")
		fmt.Fprintln(os.Stderr, "   - In Fabric Admin Portal -> Tenant Settings -> Developer settings:")
		fmt.Fprintln(os.Stderr, "     'Service principals can use Fabric APIs' must be Enabled.")
		fmt.Fprintln(os.Stderr, "3. Check if Client Secret has expired or Application (Client) ID / Tenant ID are mistyped.")
	} else if strings.Contains(msg, "no such host") || strings.Contains(msg, "network") || strings.Contains(msg, "dial") {
		fmt.Fprintln(os.Stderr, "1. Verify the SQL connection string host name from the Fabric portal:")
		fmt.Fprintln(os.Stderr, "   - Fabric Workspace -> Warehouse / Lakehouse -> Settings -> SQL connection string.")
		fmt.Fprintln(os.Stderr, "2. Ensure outbound port 1433 TCP is permitted on your network/firewall.")
	}
}
