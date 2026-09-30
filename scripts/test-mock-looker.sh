#!/usr/bin/env bash
set -euo pipefail

# Find Java binary
JAVA_BIN=""
if command -v java >/dev/null 2>&1; then
    JAVA_BIN="java"
elif [ -x "/usr/local/buildtools/java/jdk/bin/java" ]; then
    JAVA_BIN="/usr/local/buildtools/java/jdk/bin/java"
elif [ -x "${JAVA_HOME:-}/bin/java" ]; then
    JAVA_BIN="${JAVA_HOME}/bin/java"
else
    echo "[ERROR] Java binary not found. Please install Java or set JAVA_HOME."
    exit 1
fi

JAVAC_BIN=""
if command -v javac >/dev/null 2>&1; then
    JAVAC_BIN="javac"
elif [ -x "/usr/local/buildtools/java/jdk/bin/javac" ]; then
    JAVAC_BIN="/usr/local/buildtools/java/jdk/bin/javac"
elif [ -x "${JAVA_HOME:-}/bin/javac" ]; then
    JAVAC_BIN="${JAVA_HOME}/bin/javac"
else
    echo "[ERROR] javac binary not found. Please install JDK or set JAVA_HOME."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${SCRIPT_DIR}"

# Download mssql-jdbc jar if not present
JAR_PATH="test/lib/mssql-jdbc.jar"
if [ ! -f "${JAR_PATH}" ]; then
    echo "[INFO] Downloading Microsoft JDBC driver (mssql-jdbc.jar)..."
    mkdir -p test/lib
    curl -sSL -o "${JAR_PATH}" https://repo1.maven.org/maven2/com/microsoft/sqlserver/mssql-jdbc/12.8.1.jre11/mssql-jdbc-12.8.1.jre11.jar
fi

# Compile Java client
"${JAVAC_BIN}" -cp "${JAR_PATH}" -d test test/MockLookerClient.java

# Run Java client
"${JAVA_BIN}" -cp "test:${JAR_PATH}" test.MockLookerClient "$@"
