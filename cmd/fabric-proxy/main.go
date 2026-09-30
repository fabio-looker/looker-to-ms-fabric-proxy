package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql/driver"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/signal"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/microsoft/go-mssqldb/azuread"
)

// TDS Packet Types (MS-TDS 2.2.1.1)
const (
	packSQLBatch   = 0x01
	packRPCRequest = 0x03
	packReply      = 0x04
	packAttention  = 0x0E
	packLogin7     = 0x10
	packPrelogin   = 0x12
)

// TDS PreLogin Option Tokens (MS-TDS 2.2.6.5)
const (
	preloginVERSION         = 0x00
	preloginENCRYPTION      = 0x01
	preloginINSTOPT         = 0x02
	preloginTHREADID        = 0x03
	preloginMARS            = 0x04
	preloginTRACEID         = 0x05
	preloginFEDAUTHREQUIRED = 0x06
	preloginNONCEOPT        = 0x07
	preloginTERMINATOR      = 0xFF
)

// TDS PreLogin Encryption Flags
const (
	encryptOff    = 0x00
	encryptOn     = 0x01
	encryptNotSup = 0x02
	encryptReq    = 0x03
)

// TDS Tokens in Server Responses (MS-TDS 2.2.7)
const (
	tokenError     = 0xAA
	tokenInfo      = 0xAB
	tokenLoginAck  = 0xAD
	tokenEnvChange = 0xE3
	tokenDone      = 0xFD
)

type Config struct {
	ListenAddr         string
	ProxyUser          string
	ProxyPass          string
	FabricHost         string
	FabricPort         int
	FabricDB           string
	ClientID           string
	TenantID           string
	ClientSecret       string
	LogLevel           string
	LogFormat          string
	SlowQueryThreshold time.Duration
}

// ---------------------------------------------------------------------
// Structured Logger for GCE / Google Cloud Logging & Local Development
// ---------------------------------------------------------------------

type Logger struct {
	isJSON      bool
	globalDebug bool
	mu          sync.Mutex
}

func NewLogger(format, level string) *Logger {
	isJSON := strings.ToLower(format) == "json"
	// Auto-detect GCP Cloud Logging environment (e.g. K_SERVICE or GCP metadata)
	if format == "" && os.Getenv("K_SERVICE") != "" {
		isJSON = true
	}

	return &Logger{
		isJSON:      isJSON,
		globalDebug: strings.ToLower(level) == "debug",
	}
}

func (l *Logger) logEntry(severity, client, msg string, extra map[string]any) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now().UTC()

	if l.isJSON {
		entry := map[string]any{
			"time":     now.Format(time.RFC3339Nano),
			"severity": severity,
			"message":  msg,
		}
		if client != "" {
			entry["client"] = client
		}
		for k, v := range extra {
			entry[k] = v
		}
		data, _ := json.Marshal(entry)
		fmt.Println(string(data))
	} else {
		// Human-readable format for CLI & systemd journal
		timeStr := now.Format("2006-01-02 15:04:05")
		clientPrefix := ""
		if client != "" {
			clientPrefix = fmt.Sprintf("[%s] ", client)
		}
		fmt.Printf("%s [%-5s] %s%s\n", timeStr, severity, clientPrefix, msg)
	}
}

func (l *Logger) Info(client, msg string, extra ...map[string]any) {
	var m map[string]any
	if len(extra) > 0 {
		m = extra[0]
	}
	l.logEntry("INFO", client, msg, m)
}

func (l *Logger) Warn(client, msg string, extra ...map[string]any) {
	var m map[string]any
	if len(extra) > 0 {
		m = extra[0]
	}
	l.logEntry("WARNING", client, msg, m)
}

func (l *Logger) Error(client, msg string, extra ...map[string]any) {
	var m map[string]any
	if len(extra) > 0 {
		m = extra[0]
	}
	l.logEntry("ERROR", client, msg, m)
}

func (l *Logger) Debug(client, msg string, sessionDebug bool, extra ...map[string]any) {
	if !l.globalDebug && !sessionDebug {
		return
	}
	var m map[string]any
	if len(extra) > 0 {
		m = extra[0]
	}
	l.logEntry("DEBUG", client, msg, m)
}

func (l *Logger) Query(client, query string, dur time.Duration, isSlow bool, sessionDebug bool) {
	durMs := float64(dur.Microseconds()) / 1000.0

	// Truncate query preview if very long for single-line display
	preview := strings.ReplaceAll(query, "\n", " ")
	preview = strings.TrimSpace(preview)
	if len(preview) > 180 {
		preview = preview[:180] + "..."
	}

	severity := "INFO"
	if isSlow {
		severity = "WARNING"
	}

	extra := map[string]any{
		"query":       query,
		"duration_ms": durMs,
		"slow_query":  isSlow,
	}

	if l.isJSON {
		msg := "Executed query"
		if isSlow {
			msg = fmt.Sprintf("Slow query detected (took %.2fms)", durMs)
		}
		l.logEntry(severity, client, msg, extra)
	} else {
		if isSlow {
			l.logEntry("WARN", client, fmt.Sprintf("[SLOW %.1fms] %s", durMs, preview), extra)
		} else {
			l.logEntry("QUERY", client, fmt.Sprintf("[%.1fms] %s", durMs, preview), extra)
		}
	}
}

// ---------------------------------------------------------------------
// Configuration Loading
// ---------------------------------------------------------------------

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

func cleanVal(val string) string {
	val = strings.TrimSpace(val)
	if len(val) >= 2 && ((val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'')) {
		val = val[1 : len(val)-1]
	}
	return strings.TrimSpace(val)
}

func getEnvOrDefault(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return cleanVal(val)
	}
	return fallback
}

func parseConfig() (*Config, error) {
	loadEnvFile(".env")

	cfg := &Config{}

	fabricPortDefault := 1433
	if envPort := os.Getenv("FABRIC_PORT"); envPort != "" {
		if p, err := strconv.Atoi(cleanVal(envPort)); err == nil {
			fabricPortDefault = p
		}
	}

	// Listen address default: if PORT env is set (Cloud Run/GCP), default to ":$PORT", else ":14330"
	defaultListen := ":14330"
	if portEnv := os.Getenv("PORT"); portEnv != "" && os.Getenv("PROXY_LISTEN_ADDR") == "" {
		defaultListen = ":" + cleanVal(portEnv)
	}

	slowQueryMsDefault := 1000
	if envSlow := os.Getenv("PROXY_SLOW_QUERY_MS"); envSlow != "" {
		if s, err := strconv.Atoi(cleanVal(envSlow)); err == nil {
			slowQueryMsDefault = s
		}
	}

	flag.StringVar(&cfg.ListenAddr, "listen", getEnvOrDefault("PROXY_LISTEN_ADDR", defaultListen), "Proxy bind address and port")
	flag.StringVar(&cfg.ProxyUser, "proxy-user", getEnvOrDefault("PROXY_USER", "looker_user"), "Expected incoming JDBC username")
	flag.StringVar(&cfg.ProxyPass, "proxy-password", "", "Expected incoming JDBC password (defaults to PROXY_PASSWORD env var)")
	flag.StringVar(&cfg.FabricHost, "fabric-host", getEnvOrDefault("FABRIC_HOST", ""), "Fabric DW host endpoint")
	flag.IntVar(&cfg.FabricPort, "fabric-port", fabricPortDefault, "Fabric DW port (default 1433)")
	flag.StringVar(&cfg.FabricDB, "fabric-database", getEnvOrDefault("FABRIC_DATABASE", ""), "Fabric DW database name")
	flag.StringVar(&cfg.ClientID, "client-id", getEnvOrDefault("AZURE_CLIENT_ID", ""), "Entra Application (Client) ID")
	flag.StringVar(&cfg.TenantID, "tenant-id", getEnvOrDefault("AZURE_TENANT_ID", ""), "Entra Directory (Tenant) ID")
	flag.StringVar(&cfg.ClientSecret, "client-secret", "", "Entra Client Secret (defaults to AZURE_CLIENT_SECRET env var)")
	flag.StringVar(&cfg.LogLevel, "log-level", getEnvOrDefault("PROXY_LOG_LEVEL", "info"), "Log level: debug or info")
	flag.StringVar(&cfg.LogFormat, "log-format", getEnvOrDefault("PROXY_LOG_FORMAT", "text"), "Log format: text or json (for GCP Cloud Logging)")
	slowThresholdFlag := flag.Int("slow-query-ms", slowQueryMsDefault, "Threshold in ms to log slow query warning")

	flag.Parse()

	cfg.ListenAddr = cleanVal(cfg.ListenAddr)
	cfg.ProxyUser = cleanVal(cfg.ProxyUser)
	cfg.FabricHost = cleanVal(cfg.FabricHost)
	cfg.FabricDB = cleanVal(cfg.FabricDB)
	cfg.ClientID = cleanVal(cfg.ClientID)
	cfg.TenantID = cleanVal(cfg.TenantID)
	cfg.LogLevel = cleanVal(cfg.LogLevel)
	cfg.LogFormat = cleanVal(cfg.LogFormat)

	cfg.SlowQueryThreshold = time.Duration(*slowThresholdFlag) * time.Millisecond

	if cfg.ProxyPass == "" {
		cfg.ProxyPass = cleanVal(os.Getenv("PROXY_PASSWORD"))
	}
	if cfg.ClientSecret == "" {
		cfg.ClientSecret = cleanVal(os.Getenv("AZURE_CLIENT_SECRET"))
	}

	var missing []string
	if cfg.ProxyPass == "" {
		missing = append(missing, "-proxy-password or PROXY_PASSWORD")
	}
	if cfg.FabricHost == "" {
		missing = append(missing, "-fabric-host or FABRIC_HOST")
	}
	if cfg.FabricDB == "" {
		missing = append(missing, "-fabric-database or FABRIC_DATABASE")
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

// ---------------------------------------------------------------------
// Reflection Helpers to Extract Active TLS Transport from go-mssqldb
// ---------------------------------------------------------------------

func getUnexportedField(field reflect.Value) reflect.Value {
	return reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
}

func extractTransport(driverConn driver.Conn) (io.ReadWriteCloser, error) {
	val := reflect.ValueOf(driverConn)
	if val.Kind() == reflect.Pointer {
		val = val.Elem()
	}

	sessField := val.FieldByName("sess")
	if !sessField.IsValid() {
		return nil, fmt.Errorf("field 'sess' not found in %T", driverConn)
	}
	sessVal := getUnexportedField(sessField)
	if sessVal.Kind() == reflect.Pointer {
		sessVal = sessVal.Elem()
	}

	bufField := sessVal.FieldByName("buf")
	if !bufField.IsValid() {
		return nil, fmt.Errorf("field 'buf' not found in sess")
	}
	bufVal := getUnexportedField(bufField)
	if bufVal.Kind() == reflect.Pointer {
		bufVal = bufVal.Elem()
	}

	transField := bufVal.FieldByName("transport")
	if !transField.IsValid() {
		return nil, fmt.Errorf("field 'transport' not found in buf")
	}
	transVal := getUnexportedField(transField)

	if t, ok := transVal.Interface().(io.ReadWriteCloser); ok {
		return t, nil
	}
	return nil, fmt.Errorf("transport is not io.ReadWriteCloser: %T", transVal.Interface())
}

// ---------------------------------------------------------------------
// UTF-16 and TDS Packet Decoding
// ---------------------------------------------------------------------

func ucs22str(s []byte) string {
	buf := make([]uint16, len(s)/2)
	for i := 0; i < len(buf); i++ {
		buf[i] = uint16(s[2*i]) | (uint16(s[2*i+1]) << 8)
	}
	return string(utf16.Decode(buf))
}

func str2ucs2(s string) []byte {
	res := utf16.Encode([]rune(s))
	ucs2 := make([]byte, 2*len(res))
	for i := 0; i < len(res); i++ {
		ucs2[2*i] = byte(res[i])
		ucs2[2*i+1] = byte(res[i] >> 8)
	}
	return ucs2
}

func unmanglePassword(b []byte) string {
	raw := make([]byte, len(b))
	for i, ch := range b {
		v := ch ^ 0xA5
		raw[i] = ((v << 4) & 0xff) | (v >> 4)
	}
	return ucs22str(raw)
}

func generateTLSConfig() (*tls.Config, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"Fabric Authentication Proxy"},
			CommonName:   "fabric-proxy",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
		DNSNames:              []string{"localhost", "fabric-proxy"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}, nil
}

// ---------------------------------------------------------------------
// Server Implementation
// ---------------------------------------------------------------------

type ProxyServer struct {
	cfg       *Config
	logger    *Logger
	tlsConfig *tls.Config
	listener  net.Listener
	mu        sync.Mutex
	conns     map[net.Conn]struct{}
}

func NewProxyServer(cfg *Config) (*ProxyServer, error) {
	tlsCfg, err := generateTLSConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to generate TLS certificate: %w", err)
	}

	logger := NewLogger(cfg.LogFormat, cfg.LogLevel)

	return &ProxyServer{
		cfg:       cfg,
		logger:    logger,
		tlsConfig: tlsCfg,
		conns:     make(map[net.Conn]struct{}),
	}, nil
}

func (s *ProxyServer) Start() error {
	l, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.cfg.ListenAddr, err)
	}
	s.listener = l

	s.logger.Info("", "Microsoft Fabric Data Warehouse Authentication Proxy initialized", map[string]any{
		"listen_addr":       s.cfg.ListenAddr,
		"proxy_user":        s.cfg.ProxyUser,
		"upstream_host":     fmt.Sprintf("%s:%d", s.cfg.FabricHost, s.cfg.FabricPort),
		"upstream_database": s.cfg.FabricDB,
		"client_id":         s.cfg.ClientID,
		"log_level":         s.cfg.LogLevel,
		"log_format":        s.cfg.LogFormat,
		"slow_query_ms":     s.cfg.SlowQueryThreshold.Milliseconds(),
	})

	for {
		clientConn, err := s.listener.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return nil
			}
			s.logger.Error("", fmt.Sprintf("Accept error: %v", err))
			continue
		}

		s.trackConn(clientConn, true)
		go func(c net.Conn) {
			defer s.trackConn(c, false)
			defer c.Close()
			s.handleClient(c)
		}(clientConn)
	}
}

func (s *ProxyServer) trackConn(c net.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.conns[c] = struct{}{}
	} else {
		delete(s.conns, c)
	}
}

func (s *ProxyServer) Stop() {
	if s.listener != nil {
		s.listener.Close()
	}
	s.mu.Lock()
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
}

func readTDSPacket(r io.Reader) (byte, byte, []byte, error) {
	header := make([]byte, 8)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, 0, nil, err
	}

	pktType := header[0]
	pktStatus := header[1]
	pktLen := binary.BigEndian.Uint16(header[2:4])
	if pktLen < 8 {
		return 0, 0, nil, fmt.Errorf("invalid TDS packet length %d", pktLen)
	}

	payload := make([]byte, pktLen-8)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, 0, nil, err
	}

	return pktType, pktStatus, payload, nil
}

func writeTDSPacket(w io.Writer, pktType byte, status byte, payload []byte) error {
	totalLen := 8 + len(payload)
	header := make([]byte, 8)
	header[0] = pktType
	header[1] = status
	binary.BigEndian.PutUint16(header[2:4], uint16(totalLen))
	header[4] = 0 // SPID
	header[5] = 0
	header[6] = 1 // PacketID
	header[7] = 0 // Window

	if _, err := w.Write(header); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func sendTDSError(w io.Writer, errorMsg string) {
	var buf bytes.Buffer

	buf.WriteByte(tokenError)

	var errPayload bytes.Buffer
	binary.Write(&errPayload, binary.LittleEndian, int32(18456)) // Error number (Login failed)
	errPayload.WriteByte(1)                                     // State
	errPayload.WriteByte(14)                                    // Class / Severity (14 = auth error)

	msgUcs2 := str2ucs2(errorMsg)
	binary.Write(&errPayload, binary.LittleEndian, uint16(len(msgUcs2)/2))
	errPayload.Write(msgUcs2)

	srvUcs2 := str2ucs2("fabric-proxy")
	errPayload.WriteByte(byte(len(srvUcs2) / 2))
	errPayload.Write(srvUcs2)

	errPayload.WriteByte(0)                                     // ProcName BVarChar
	binary.Write(&errPayload, binary.LittleEndian, int32(1))    // LineNo int32

	binary.Write(&buf, binary.LittleEndian, uint16(errPayload.Len()))
	buf.Write(errPayload.Bytes())

	buf.WriteByte(tokenDone)
	binary.Write(&buf, binary.LittleEndian, uint16(0x0002)) // Status: DONE_ERROR
	binary.Write(&buf, binary.LittleEndian, uint16(0))      // CurCmd
	binary.Write(&buf, binary.LittleEndian, uint64(0))      // RowCount

	_ = writeTDSPacket(w, packReply, 0x01, buf.Bytes())
}

func sendLoginAck(w io.Writer, srvName string) error {
	var buf bytes.Buffer

	buf.WriteByte(tokenLoginAck)
	srvBytes := str2ucs2(srvName)
	loginAckLen := uint16(1 + 4 + 1 + len(srvBytes) + 4)
	binary.Write(&buf, binary.LittleEndian, loginAckLen)

	buf.WriteByte(1)                                         // Interface: SQL_TSQL
	binary.Write(&buf, binary.BigEndian, uint32(0x74000004)) // TDS 7.4
	buf.WriteByte(byte(len(srvBytes) / 2))                   // ProgName length in chars
	buf.Write(srvBytes)                                      // ProgName
	binary.Write(&buf, binary.BigEndian, uint32(0x0F000000)) // ProgVer: 15.0

	buf.WriteByte(tokenDone)
	binary.Write(&buf, binary.LittleEndian, uint16(0x0000)) // Status: DONE_FINAL
	binary.Write(&buf, binary.LittleEndian, uint16(0))      // CurCmd
	binary.Write(&buf, binary.LittleEndian, uint64(0))      // RowCount

	return writeTDSPacket(w, packReply, 0x01, buf.Bytes())
}

type ClientLoginInfo struct {
	RawUser   string
	CleanUser string
	Password  string
	Database  string
	HostName  string
	AppName   string
	IsDebug   bool
}

func (s *ProxyServer) handleClient(clientConn net.Conn) {
	clientAddr := clientConn.RemoteAddr().String()
	sessionStart := time.Now()

	s.logger.Info(clientAddr, "Incoming connection accepted")

	// Step 1: Read PreLogin packet from client
	pktType, _, preloginData, err := readTDSPacket(clientConn)
	if err != nil {
		s.logger.Error(clientAddr, fmt.Sprintf("Failed to read PreLogin packet: %v", err))
		return
	}
	if pktType != packPrelogin {
		s.logger.Error(clientAddr, fmt.Sprintf("Expected PreLogin packet (0x12), got 0x%02x", pktType))
		return
	}

	clientEncrypt := parsePreloginEncryption(preloginData)

	var commConn net.Conn = clientConn
	if clientEncrypt == encryptOn || clientEncrypt == encryptReq {
		s.logger.Debug(clientAddr, "Client requested TLS encryption during PreLogin", false)
		if err := sendPreloginResponse(clientConn, encryptOn); err != nil {
			s.logger.Error(clientAddr, fmt.Sprintf("Failed to write PreLogin response: %v", err))
			return
		}
		tlsHandshake := newTdsHandshakeConn(clientConn)
		tlsConn := tls.Server(tlsHandshake, s.tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			s.logger.Error(clientAddr, fmt.Sprintf("TLS handshake failed: %v", err))
			return
		}
		commConn = tlsConn
	} else {
		if err := sendPreloginResponse(clientConn, encryptNotSup); err != nil {
			s.logger.Error(clientAddr, fmt.Sprintf("Failed to write PreLogin response: %v", err))
			return
		}
	}

	// Step 2: Read LOGIN7 packet
	pktType, _, loginData, err := readTDSPacket(commConn)
	if err != nil {
		s.logger.Error(clientAddr, fmt.Sprintf("Failed to read LOGIN7 packet: %v", err))
		return
	}
	if pktType != packLogin7 {
		s.logger.Error(clientAddr, fmt.Sprintf("Expected LOGIN7 packet (0x10), got 0x%02x", pktType))
		return
	}

	clientInfo, err := parseLogin7(loginData)
	if err != nil {
		s.logger.Error(clientAddr, fmt.Sprintf("Failed to parse LOGIN7 packet: %v", err))
		sendTDSError(commConn, "Corrupted or invalid LOGIN7 packet")
		return
	}

	// Dynamic debug toggle detection:
	// 1. Global config LogLevel == "debug"
	// 2. applicationName contains "debug"
	// 3. username contains "#debug" or "?debug=true" or ";debug=true"
	// 4. databaseName contains "debug"
	sessionDebug := s.logger.globalDebug ||
		strings.Contains(strings.ToLower(clientInfo.RawUser), "debug") ||
		strings.Contains(strings.ToLower(clientInfo.AppName), "debug") ||
		strings.Contains(strings.ToLower(clientInfo.Database), "debug")

	if sessionDebug && !s.logger.globalDebug {
		s.logger.Info(clientAddr, "DEBUG logging dynamically enabled for this session via JDBC parameters")
	}

	s.logger.Debug(clientAddr, "LOGIN7 metadata received", sessionDebug, map[string]any{
		"raw_user":   clientInfo.RawUser,
		"clean_user": clientInfo.CleanUser,
		"database":   clientInfo.Database,
		"app_name":   clientInfo.AppName,
		"host_name":  clientInfo.HostName,
	})

	// Step 3: Authenticate incoming credentials
	if clientInfo.CleanUser != s.cfg.ProxyUser || clientInfo.Password != s.cfg.ProxyPass {
		s.logger.Warn(clientAddr, fmt.Sprintf("Authentication failed for user '%s'", clientInfo.CleanUser))
		sendTDSError(commConn, fmt.Sprintf("Login failed for user '%s'.", clientInfo.CleanUser))
		return
	}

	targetDB := s.cfg.FabricDB
	if clientInfo.Database != "" {
		targetDB = clientInfo.Database
	}

	s.logger.Info(clientAddr, fmt.Sprintf("Authenticated user '%s' (%s). Connecting upstream to Fabric DW...", clientInfo.CleanUser, clientInfo.AppName), map[string]any{
		"user":     clientInfo.CleanUser,
		"app":      clientInfo.AppName,
		"host":     clientInfo.HostName,
		"database": targetDB,
	})

	// Step 4: Dial Microsoft Fabric DW using Entra ID Service Principal
	connectStart := time.Now()
	upstreamConnStr := fmt.Sprintf("server=%s;port=%d;database=%s;user id=%s@%s;password=%s;fedauth=ActiveDirectoryServicePrincipal;encrypt=true;TrustServerCertificate=false",
		s.cfg.FabricHost, s.cfg.FabricPort, targetDB, s.cfg.ClientID, s.cfg.TenantID, s.cfg.ClientSecret)

	connector, err := azuread.NewConnector(upstreamConnStr)
	if err != nil {
		s.logger.Error(clientAddr, fmt.Sprintf("Failed to create Fabric connector: %v", err))
		sendTDSError(commConn, "Proxy failed to initialize Fabric DW connector")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	driverConn, err := connector.Connect(ctx)
	if err != nil {
		s.logger.Error(clientAddr, fmt.Sprintf("Failed to connect to Fabric DW: %v", err))
		sendTDSError(commConn, fmt.Sprintf("Proxy failed to connect to Fabric DW: %v", err))
		return
	}
	defer driverConn.Close()

	fabricTransport, err := extractTransport(driverConn)
	if err != nil {
		s.logger.Error(clientAddr, fmt.Sprintf("Failed to extract Fabric transport: %v", err))
		sendTDSError(commConn, "Internal proxy transport error")
		return
	}

	upstreamLatency := time.Since(connectStart)
	s.logger.Debug(clientAddr, fmt.Sprintf("Fabric DW upstream connected in %v (Entra token acquired + TLS established)", upstreamLatency.Round(time.Millisecond)), sessionDebug)

	// Step 5: Send LOGINACK to client
	if err := sendLoginAck(commConn, "Microsoft Fabric DW (Proxy)"); err != nil {
		s.logger.Error(clientAddr, fmt.Sprintf("Failed to send LOGINACK: %v", err))
		return
	}

	s.logger.Info(clientAddr, "Tunnel established. Relaying TDS queries to Fabric DW...")

	// Step 6: Full bidirectional forwarding with query execution timing
	var bytesRx uint64 // from client
	var bytesTx uint64 // to client
	var queryCount uint64

	var queryMu sync.Mutex
	var currentQuery string
	var queryStart time.Time

	errc := make(chan error, 2)

	// Pump: Client -> Fabric DW
	go func() {
		buf := make([]byte, 32768)
		for {
			n, err := commConn.Read(buf)
			if n > 0 {
				atomic.AddUint64(&bytesRx, uint64(n))

				pktType := buf[0]
				pktStatus := buf[1]

				if pktType == packSQLBatch && n > 8 {
					sqlText := extractSQLFromBatch(buf[8:n])
					if sqlText != "" {
						queryMu.Lock()
						currentQuery = sqlText
						if pktStatus&0x01 != 0 { // EOM
							queryStart = time.Now()
							atomic.AddUint64(&queryCount, 1)
						}
						queryMu.Unlock()
					}
				}

				s.logger.Debug(clientAddr, fmt.Sprintf("TDS tx -> Fabric: type=0x%02x status=0x%02x len=%d", pktType, pktStatus, n), sessionDebug)

				if _, werr := fabricTransport.Write(buf[:n]); werr != nil {
					errc <- werr
					return
				}
			}
			if err != nil {
				errc <- err
				return
			}
		}
	}()

	// Pump: Fabric DW -> Client
	go func() {
		buf := make([]byte, 32768)
		for {
			n, err := fabricTransport.Read(buf)
			if n > 0 {
				atomic.AddUint64(&bytesTx, uint64(n))

				pktType := buf[0]
				pktStatus := buf[1]

				s.logger.Debug(clientAddr, fmt.Sprintf("TDS rx <- Fabric: type=0x%02x status=0x%02x len=%d", pktType, pktStatus, n), sessionDebug)

				// When Fabric completes the reply message (EOM = 0x01)
				if pktStatus&0x01 != 0 {
					queryMu.Lock()
					if !queryStart.IsZero() && currentQuery != "" {
						dur := time.Since(queryStart)
						isSlow := dur >= s.cfg.SlowQueryThreshold
						s.logger.Query(clientAddr, currentQuery, dur, isSlow, sessionDebug)
						queryStart = time.Time{}
						currentQuery = ""
					}
					queryMu.Unlock()
				}

				if _, werr := commConn.Write(buf[:n]); werr != nil {
					errc <- werr
					return
				}
			}
			if err != nil {
				errc <- err
				return
			}
		}
	}()

	cause := <-errc

	sessionDur := time.Since(sessionStart).Round(time.Millisecond)
	totalRx := atomic.LoadUint64(&bytesRx)
	totalTx := atomic.LoadUint64(&bytesTx)
	totalQueries := atomic.LoadUint64(&queryCount)

	sessionSummary := map[string]any{
		"session_duration_ms": sessionDur.Milliseconds(),
		"total_queries":       totalQueries,
		"bytes_received":      totalRx,
		"bytes_sent":          totalTx,
	}

	if cause != nil && cause != io.EOF {
		s.logger.Info(clientAddr, fmt.Sprintf("Session ended: duration=%s, queries=%d, rx=%d bytes, tx=%d bytes (closed with: %v)",
			sessionDur, totalQueries, totalRx, totalTx, cause), sessionSummary)
	} else {
		s.logger.Info(clientAddr, fmt.Sprintf("Session ended: duration=%s, queries=%d, rx=%d bytes, tx=%d bytes (graceful close)",
			sessionDur, totalQueries, totalRx, totalTx), sessionSummary)
	}
}

func parsePreloginEncryption(data []byte) byte {
	pos := 0
	for pos < len(data) {
		token := data[pos]
		if token == preloginTERMINATOR {
			break
		}
		if pos+5 > len(data) {
			break
		}
		offset := binary.BigEndian.Uint16(data[pos+1 : pos+3])
		length := binary.BigEndian.Uint16(data[pos+3 : pos+5])
		if token == preloginENCRYPTION && int(offset)+int(length) <= len(data) && length > 0 {
			return data[offset]
		}
		pos += 5
	}
	return encryptOff
}

func sendPreloginResponse(w io.Writer, encryptSetting byte) error {
	fields := []struct {
		token byte
		val   []byte
	}{
		{preloginVERSION, []byte{15, 0, 0, 0, 0, 0}},
		{preloginENCRYPTION, []byte{encryptSetting}},
		{preloginINSTOPT, []byte{0}},
		{preloginTHREADID, []byte{0, 0, 0, 0}},
		{preloginMARS, []byte{0}},
	}

	offset := uint16(5*len(fields) + 1)
	var hdr bytes.Buffer
	var data bytes.Buffer

	for _, f := range fields {
		hdr.WriteByte(f.token)
		binary.Write(&hdr, binary.BigEndian, offset)
		binary.Write(&hdr, binary.BigEndian, uint16(len(f.val)))
		offset += uint16(len(f.val))
		data.Write(f.val)
	}
	hdr.WriteByte(preloginTERMINATOR)

	payload := append(hdr.Bytes(), data.Bytes()...)
	return writeTDSPacket(w, packReply, 0x01, payload)
}

func parseLogin7(payload []byte) (ClientLoginInfo, error) {
	var info ClientLoginInfo
	if len(payload) < 94 {
		return info, fmt.Errorf("LOGIN7 payload too short (%d bytes)", len(payload))
	}

	hOffset := binary.LittleEndian.Uint16(payload[36:38])
	hLen := binary.LittleEndian.Uint16(payload[38:40])
	uOffset := binary.LittleEndian.Uint16(payload[40:42])
	uLen := binary.LittleEndian.Uint16(payload[42:44])
	pOffset := binary.LittleEndian.Uint16(payload[44:46])
	pLen := binary.LittleEndian.Uint16(payload[46:48])
	aOffset := binary.LittleEndian.Uint16(payload[48:50])
	aLen := binary.LittleEndian.Uint16(payload[50:52])
	dOffset := binary.LittleEndian.Uint16(payload[68:70])
	dLen := binary.LittleEndian.Uint16(payload[70:72])

	if int(hOffset)+int(hLen)*2 <= len(payload) {
		info.HostName = ucs22str(payload[hOffset : hOffset+hLen*2])
	}
	if int(uOffset)+int(uLen)*2 <= len(payload) {
		info.RawUser = ucs22str(payload[uOffset : uOffset+uLen*2])
	}
	if int(pOffset)+int(pLen)*2 <= len(payload) {
		info.Password = unmanglePassword(payload[pOffset : pOffset+pLen*2])
	}
	if int(aOffset)+int(aLen)*2 <= len(payload) {
		info.AppName = ucs22str(payload[aOffset : aOffset+aLen*2])
	}
	if int(dOffset)+int(dLen)*2 <= len(payload) {
		info.Database = ucs22str(payload[dOffset : dOffset+dLen*2])
	}

	// Clean username: strip any #debug, ?debug=true, ;debug=true
	info.CleanUser = info.RawUser
	for _, sep := range []string{"#", "?", ";"} {
		if idx := strings.Index(info.CleanUser, sep); idx != -1 {
			info.CleanUser = info.CleanUser[:idx]
		}
	}

	return info, nil
}

func extractSQLFromBatch(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	totalHeadersLen := binary.LittleEndian.Uint32(payload[0:4])
	if int(totalHeadersLen) >= len(payload) {
		return ""
	}
	sqlBytes := payload[totalHeadersLen:]
	return strings.TrimSpace(ucs22str(sqlBytes))
}

type tdsHandshakeConn struct {
	conn      net.Conn
	readBuf   bytes.Buffer
	writeBuf  bytes.Buffer
	handshake bool
}

func newTdsHandshakeConn(c net.Conn) *tdsHandshakeConn {
	return &tdsHandshakeConn{conn: c, handshake: true}
}

func (c *tdsHandshakeConn) Read(b []byte) (n int, err error) {
	if !c.handshake {
		return c.conn.Read(b)
	}
	if c.readBuf.Len() > 0 {
		return c.readBuf.Read(b)
	}

	pktType, _, payload, err := readTDSPacket(c.conn)
	if err != nil {
		return 0, err
	}
	if pktType != packPrelogin && pktType != packReply {
		c.handshake = false
		c.readBuf.Write(payload)
		return c.readBuf.Read(b)
	}
	c.readBuf.Write(payload)
	return c.readBuf.Read(b)
}

func (c *tdsHandshakeConn) Write(b []byte) (n int, err error) {
	if !c.handshake {
		return c.conn.Write(b)
	}
	if err := writeTDSPacket(c.conn, packPrelogin, 0x01, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *tdsHandshakeConn) Close() error                       { return c.conn.Close() }
func (c *tdsHandshakeConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *tdsHandshakeConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *tdsHandshakeConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *tdsHandshakeConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *tdsHandshakeConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

func main() {
	cfg, err := parseConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n\n", err)
		os.Exit(1)
	}

	server, err := NewProxyServer(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize server: %v\n", err)
		os.Exit(1)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigCh
		server.logger.Info("", "Shutdown signal received. Stopping proxy server...")
		server.Stop()
	}()

	if err := server.Start(); err != nil {
		server.logger.Error("", fmt.Sprintf("Server exited with error: %v", err))
		os.Exit(1)
	}
}
