package test;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.Map;

/**
 * MockLookerClient simulates Looker connecting to Microsoft Fabric DW
 * through the local fabric-proxy using the official Microsoft JDBC Driver.
 */
public class MockLookerClient {

    private static Map<String, String> loadEnvFile(String path) {
        Map<String, String> env = new HashMap<>();
        File file = new File(path);
        if (!file.exists()) {
            return env;
        }
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                if (line.startsWith("export ")) {
                    line = line.substring(7).trim();
                }
                int eq = line.indexOf('=');
                if (eq > 0) {
                    String key = line.substring(0, eq).trim();
                    String val = line.substring(eq + 1).trim();
                    if ((val.startsWith("\"") && val.endsWith("\"")) || (val.startsWith("'") && val.endsWith("'"))) {
                        val = val.substring(1, val.length() - 1);
                    }
                    env.put(key, val);
                }
            }
        } catch (Exception e) {
            System.err.println("Warning: Could not read " + path + ": " + e.getMessage());
        }
        return env;
    }

    private static String getEnvOrFallback(Map<String, String> env, String key, String fallback) {
        String sysEnv = System.getenv(key);
        if (sysEnv != null && !sysEnv.trim().isEmpty()) {
            return sysEnv.trim();
        }
        String fileEnv = env.get(key);
        if (fileEnv != null && !fileEnv.trim().isEmpty()) {
            return fileEnv.trim();
        }
        return fallback;
    }

    public static void main(String[] args) {
        System.out.println("================================================================");
        System.out.println("  Mock Looker JDBC Client (Official Microsoft JDBC Driver)");
        System.out.println("================================================================");

        Map<String, String> env = loadEnvFile(".env");

        String host = getEnvOrFallback(env, "MOCK_HOST", "localhost");
        String port = getEnvOrFallback(env, "MOCK_PORT", "14330");
        String user = getEnvOrFallback(env, "PROXY_USER", "looker_user");
        String pass = getEnvOrFallback(env, "PROXY_PASSWORD", "");
        String database = getEnvOrFallback(env, "FABRIC_DATABASE", "");
        String table = getEnvOrFallback(env, "FABRIC_TABLE", "");
        String appName = getEnvOrFallback(env, "MOCK_APP_NAME", "Looker");

        // Parse command line flags: --debug, --encrypt
        boolean encrypt = false;
        for (String arg : args) {
            if ("--debug".equalsIgnoreCase(arg)) {
                appName = "Looker-debug";
            }
            if ("--encrypt".equalsIgnoreCase(arg)) {
                encrypt = true;
            }
        }

        if (pass.isEmpty()) {
            System.err.println("[ERROR] PROXY_PASSWORD is not set in environment or .env file!");
            System.exit(1);
        }

        // Construct standard Looker JDBC connection string
        String jdbcUrl = String.format(
            "jdbc:sqlserver://%s:%s;databaseName=%s;user=%s;password=%s;encrypt=%s;trustServerCertificate=true;applicationName=%s;",
            host, port, database, user, pass, encrypt ? "true" : "false", appName
        );

        String maskedUrl = jdbcUrl.replace(pass, "********");
        System.out.println("\n[1/4] Connecting via JDBC:");
        System.out.println("      URL: " + maskedUrl);
        System.out.println("      Client Application Name: " + appName);
        System.out.println("      TLS Encryption to Proxy: " + (encrypt ? "Enabled" : "Disabled (Plain TCP)"));

        long startConnect = System.currentTimeMillis();
        try (Connection conn = DriverManager.getConnection(jdbcUrl)) {
            long connectDuration = System.currentTimeMillis() - startConnect;
            System.out.printf("[2/4] Successfully connected to proxy in %d ms!\n", connectDuration);

            // Print metadata
            DatabaseMetaData meta = conn.getMetaData();
            System.out.println("\n[3/4] Connection Metadata (from Fabric DW via Proxy):");
            System.out.println("      Database Product: " + meta.getDatabaseProductName());
            System.out.println("      Database Version: " + meta.getDatabaseProductVersion());
            System.out.println("      Driver Name:      " + meta.getDriverName());
            System.out.println("      Driver Version:   " + meta.getDriverVersion());

            // Run Looker-style queries
            System.out.println("\n[4/4] Executing Looker-style literal SQL queries...");

            try (Statement stmt = conn.createStatement()) {
                // Test Query 1: Validation query
                runQuery(stmt, "SELECT 1 AS looker_test_val, 'Fabric Proxy Connected' AS status;");

                // Test Query 2: Current user and timestamp
                runQuery(stmt, "SELECT CURRENT_USER AS current_user_name, GETUTCDATE() AS server_time_utc;");

                // Test Query 3: Optional table query
                if (table != null && !table.trim().isEmpty()) {
                    runQuery(stmt, "SELECT COUNT(*) AS total_rows FROM " + table + ";");
                }
            }

            System.out.println("\n================================================================");
            System.out.println("  All Mock Looker queries executed successfully!");
            System.out.println("================================================================");

        } catch (SQLException e) {
            System.err.println("\n[ERROR] JDBC Connection / Query failed!");
            System.err.println("        SQLState: " + e.getSQLState());
            System.err.println("        ErrorCode: " + e.getErrorCode());
            System.err.println("        Message: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static void runQuery(Statement stmt, String sql) throws SQLException {
        System.out.println("\n--- Executing SQL: " + sql);
        long start = System.currentTimeMillis();
        try (ResultSet rs = stmt.executeQuery(sql)) {
            long duration = System.currentTimeMillis() - start;
            ResultSetMetaData meta = rs.getMetaData();
            int colCount = meta.getColumnCount();

            // Print header
            StringBuilder header = new StringBuilder();
            for (int i = 1; i <= colCount; i++) {
                if (i > 1) header.append(" | ");
                header.append(meta.getColumnLabel(i));
            }
            System.out.println("    " + header.toString());
            System.out.println("    " + "-".repeat(Math.max(20, header.length())));

            // Print rows
            int rowCount = 0;
            while (rs.next()) {
                rowCount++;
                StringBuilder row = new StringBuilder();
                for (int i = 1; i <= colCount; i++) {
                    if (i > 1) row.append(" | ");
                    row.append(rs.getString(i));
                }
                System.out.println("    " + row.toString());
            }
            System.out.printf("    (%d row(s) returned in %d ms)\n", rowCount, duration);
        }
    }
}
