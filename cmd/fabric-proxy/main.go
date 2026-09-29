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
	ListenAddr   string
	ProxyUser    string
	ProxyPass    string
	FabricHost   string
	FabricPort   int
	FabricDB     string
	ClientID     string
	TenantID     string
	ClientSecret string
	LogLevel     string
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

func parseConfig() (*Config, error) {
	loadEnvFile(".env")

	cfg := &Config{}

	fabricPortDefault := 1433
	if envPort := os.Getenv("FABRIC_PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil {
			fabricPortDefault = p
		}
	}

	flag.StringVar(&cfg.ListenAddr, "listen", getEnvOrDefault("PROXY_LISTEN_ADDR", ":14330"), "Proxy bind address and port")
	flag.StringVar(&cfg.ProxyUser, "proxy-user", getEnvOrDefault("PROXY_USER", "looker_user"), "Expected incoming JDBC username")
	flag.StringVar(&cfg.ProxyPass, "proxy-password", "", "Expected incoming JDBC password (defaults to PROXY_PASSWORD env var)")
	flag.StringVar(&cfg.FabricHost, "fabric-host", getEnvOrDefault("FABRIC_HOST", ""), "Fabric DW host endpoint")
	flag.IntVar(&cfg.FabricPort, "fabric-port", fabricPortDefault, "Fabric DW port (default 1433)")
	flag.StringVar(&cfg.FabricDB, "fabric-database", getEnvOrDefault("FABRIC_DATABASE", ""), "Fabric DW database name")
	flag.StringVar(&cfg.ClientID, "client-id", getEnvOrDefault("AZURE_CLIENT_ID", ""), "Entra Application (Client) ID")
	flag.StringVar(&cfg.TenantID, "tenant-id", getEnvOrDefault("AZURE_TENANT_ID", ""), "Entra Directory (Tenant) ID")
	flag.StringVar(&cfg.ClientSecret, "client-secret", "", "Entra Client Secret (defaults to AZURE_CLIENT_SECRET env var)")
	flag.StringVar(&cfg.LogLevel, "log-level", getEnvOrDefault("PROXY_LOG_LEVEL", "info"), "Log level: debug or info")

	flag.Parse()

	if cfg.ProxyPass == "" {
		cfg.ProxyPass = os.Getenv("PROXY_PASSWORD")
	}
	if cfg.ClientSecret == "" {
		cfg.ClientSecret = os.Getenv("AZURE_CLIENT_SECRET")
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

// Reflection helpers to extract the underlying active TLS transport from mssql.Conn
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

// UTF-16 and TDS string helpers
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

// Generate an in-memory self-signed TLS certificate if the JDBC client requests TLS
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

type ProxyServer struct {
	cfg       *Config
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

	return &ProxyServer{
		cfg:       cfg,
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

	fmt.Println("==================================================")
	fmt.Println("Microsoft Fabric Data Warehouse Authentication Proxy")
	fmt.Println("==================================================")
	fmt.Printf("Listening on:       %s\n", s.cfg.ListenAddr)
	fmt.Printf("Proxy User:         %s\n", s.cfg.ProxyUser)
	fmt.Printf("Upstream Host:      %s:%d\n", s.cfg.FabricHost, s.cfg.FabricPort)
	fmt.Printf("Upstream Database:  %s\n", s.cfg.FabricDB)
	fmt.Printf("Upstream Auth:      Entra ID SP (Client ID: %s)\n", s.cfg.ClientID)
	fmt.Println("Ready to accept incoming JDBC connections from Looker.")
	fmt.Println("--------------------------------------------------")

	for {
		clientConn, err := s.listener.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return nil
			}
			fmt.Printf("[ERROR] Accept error: %v\n", err)
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

// readTDSPacket reads a full TDS packet (8-byte header + payload)
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

// writeTDSPacket writes a single TDS packet
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

// sendTDSError sends a TDS Error token (0xAA) followed by DONE (0xFD)
func sendTDSError(w io.Writer, errorMsg string) {
	var buf bytes.Buffer

	// Token: ERROR (0xAA)
	buf.WriteByte(tokenError)

	var errPayload bytes.Buffer
	binary.Write(&errPayload, binary.LittleEndian, int32(18456)) // Error number (Login failed)
	errPayload.WriteByte(1)                                     // State
	errPayload.WriteByte(14)                                    // Class / Severity (14 = auth error)

	// UsVarChar message
	msgUcs2 := str2ucs2(errorMsg)
	binary.Write(&errPayload, binary.LittleEndian, uint16(len(msgUcs2)/2))
	errPayload.Write(msgUcs2)

	// ServerName BVarChar
	srvUcs2 := str2ucs2("fabric-proxy")
	errPayload.WriteByte(byte(len(srvUcs2) / 2))
	errPayload.Write(srvUcs2)

	// ProcName BVarChar
	errPayload.WriteByte(0)

	// LineNo int32
	binary.Write(&errPayload, binary.LittleEndian, int32(1))

	// Write error token length + payload
	binary.Write(&buf, binary.LittleEndian, uint16(errPayload.Len()))
	buf.Write(errPayload.Bytes())

	// Token: DONE (0xFD)
	buf.WriteByte(tokenDone)
	binary.Write(&buf, binary.LittleEndian, uint16(0x0002)) // Status: DONE_ERROR
	binary.Write(&buf, binary.LittleEndian, uint16(0))      // CurCmd
	binary.Write(&buf, binary.LittleEndian, uint64(0))      // RowCount

	_ = writeTDSPacket(w, packReply, 0x01, buf.Bytes())
}

// sendLoginAck sends LOGINACK (0xAD) and DONE (0xFD)
func sendLoginAck(w io.Writer, srvName string) error {
	var buf bytes.Buffer

	// Token: LOGINACK (0xAD)
	buf.WriteByte(tokenLoginAck)
	srvBytes := str2ucs2(srvName)
	loginAckLen := uint16(1 + 4 + 1 + len(srvBytes) + 4)
	binary.Write(&buf, binary.LittleEndian, loginAckLen)

	buf.WriteByte(1)                                                // Interface: SQL_TSQL
	binary.Write(&buf, binary.BigEndian, uint32(0x74000004))        // TDS 7.4
	buf.WriteByte(byte(len(srvBytes) / 2))                          // ProgName length in characters
	buf.Write(srvBytes)                                             // ProgName
	binary.Write(&buf, binary.BigEndian, uint32(0x0F000000))        // ProgVer: 15.0

	// Token: DONE (0xFD)
	buf.WriteByte(tokenDone)
	binary.Write(&buf, binary.LittleEndian, uint16(0x0000)) // Status: DONE_FINAL
	binary.Write(&buf, binary.LittleEndian, uint16(0))      // CurCmd
	binary.Write(&buf, binary.LittleEndian, uint64(0))      // RowCount

	return writeTDSPacket(w, packReply, 0x01, buf.Bytes())
}

func (s *ProxyServer) handleClient(clientConn net.Conn) {
	clientAddr := clientConn.RemoteAddr().String()
	fmt.Printf("[INFO] [%s] New incoming connection\n", clientAddr)

	// Step 1: Read PreLogin packet from client
	pktType, _, preloginData, err := readTDSPacket(clientConn)
	if err != nil {
		fmt.Printf("[ERROR] [%s] Failed to read PreLogin packet: %v\n", clientAddr, err)
		return
	}
	if pktType != packPrelogin {
		fmt.Printf("[ERROR] [%s] Expected PreLogin packet (0x12), got 0x%02x\n", clientAddr, pktType)
		return
	}

	// Inspect client encryption request in PreLogin
	clientEncrypt := parsePreloginEncryption(preloginData)
	if s.cfg.LogLevel == "debug" {
		fmt.Printf("[DEBUG] [%s] Client prelogin encryption option: %d\n", clientAddr, clientEncrypt)
	}

	// Reply with PreLogin response
	// If client requested encryption (encryptOn / encryptReq), offer encryptOn and do TLS.
	// Otherwise offer encryptNotSup (unencrypted local communication).
	var commConn net.Conn = clientConn
	if clientEncrypt == encryptOn || clientEncrypt == encryptReq {
		// Send PreLogin response indicating encryption is ON
		if err := sendPreloginResponse(clientConn, encryptOn); err != nil {
			fmt.Printf("[ERROR] [%s] Failed to write PreLogin response: %v\n", clientAddr, err)
			return
		}
		// Wrap clientConn in TDS TLS handshake wrapper
		tlsHandshake := newTdsHandshakeConn(clientConn)
		tlsConn := tls.Server(tlsHandshake, s.tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			fmt.Printf("[ERROR] [%s] TLS handshake failed: %v\n", clientAddr, err)
			return
		}
		commConn = tlsConn
	} else {
		// Send PreLogin response with encryptNotSup
		if err := sendPreloginResponse(clientConn, encryptNotSup); err != nil {
			fmt.Printf("[ERROR] [%s] Failed to write PreLogin response: %v\n", clientAddr, err)
			return
		}
	}

	// Step 2: Read LOGIN7 packet
	pktType, _, loginData, err := readTDSPacket(commConn)
	if err != nil {
		fmt.Printf("[ERROR] [%s] Failed to read LOGIN7 packet: %v\n", clientAddr, err)
		return
	}
	if pktType != packLogin7 {
		fmt.Printf("[ERROR] [%s] Expected LOGIN7 packet (0x10), got 0x%02x\n", clientAddr, pktType)
		return
	}

	username, password, database, err := parseLogin7(loginData)
	if err != nil {
		fmt.Printf("[ERROR] [%s] Failed to parse LOGIN7 packet: %v\n", clientAddr, err)
		sendTDSError(commConn, "Corrupted or invalid LOGIN7 packet")
		return
	}

	// Step 3: Authenticate incoming credentials
	if username != s.cfg.ProxyUser || password != s.cfg.ProxyPass {
		fmt.Printf("[WARN] [%s] Authentication failed for user '%s'\n", clientAddr, username)
		sendTDSError(commConn, fmt.Sprintf("Login failed for user '%s'.", username))
		return
	}

	targetDB := s.cfg.FabricDB
	if database != "" {
		targetDB = database
	}
	fmt.Printf("[INFO] [%s] Authenticated user '%s' successfully. Connecting to Fabric DW (%s)...\n", clientAddr, username, targetDB)

	// Step 4: Dial Microsoft Fabric DW using Entra ID Service Principal
	upstreamConnStr := fmt.Sprintf("server=%s;port=%d;database=%s;user id=%s@%s;password=%s;fedauth=ActiveDirectoryServicePrincipal;encrypt=true;TrustServerCertificate=false",
		s.cfg.FabricHost, s.cfg.FabricPort, targetDB, s.cfg.ClientID, s.cfg.TenantID, s.cfg.ClientSecret)

	connector, err := azuread.NewConnector(upstreamConnStr)
	if err != nil {
		fmt.Printf("[ERROR] [%s] Failed to create Fabric connector: %v\n", clientAddr, err)
		sendTDSError(commConn, "Proxy failed to initialize Fabric DW connector")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	driverConn, err := connector.Connect(ctx)
	if err != nil {
		fmt.Printf("[ERROR] [%s] Failed to connect to Fabric DW: %v\n", clientAddr, err)
		sendTDSError(commConn, fmt.Sprintf("Proxy failed to connect to Fabric DW: %v", err))
		return
	}
	defer driverConn.Close()

	// Extract active TLS transport to Fabric DW
	fabricTransport, err := extractTransport(driverConn)
	if err != nil {
		fmt.Printf("[ERROR] [%s] Failed to extract Fabric transport: %v\n", clientAddr, err)
		sendTDSError(commConn, "Internal proxy transport error")
		return
	}

	// Step 5: Send LOGINACK to client
	if err := sendLoginAck(commConn, "Microsoft Fabric DW (Proxy)"); err != nil {
		fmt.Printf("[ERROR] [%s] Failed to send LOGINACK: %v\n", clientAddr, err)
		return
	}

	fmt.Printf("[INFO] [%s] Tunnel established. Relaying TDS queries to Fabric DW...\n", clientAddr)

	// Step 6: Bidirectional forwarding between Looker and Fabric DW
	errc := make(chan error, 2)

	// Client -> Fabric DW
	go func() {
		// Wrap reader to optionally inspect/log SQL queries
		buf := make([]byte, 32768)
		for {
			n, err := commConn.Read(buf)
			if n > 0 {
				if buf[0] == packSQLBatch && n > 8 {
					// Extract SQL query for logging
					sqlText := extractSQLFromBatch(buf[8:n])
					if sqlText != "" {
						firstLine := strings.Split(sqlText, "\n")[0]
						if len(firstLine) > 120 {
							firstLine = firstLine[:120] + "..."
						}
						fmt.Printf("[QUERY] [%s] %s\n", clientAddr, firstLine)
					}
				}
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

	// Fabric DW -> Client
	go func() {
		_, err := io.Copy(commConn, fabricTransport)
		errc <- err
	}()

	cause := <-errc
	if cause != nil && cause != io.EOF {
		fmt.Printf("[INFO] [%s] Connection closed: %v\n", clientAddr, cause)
	} else {
		fmt.Printf("[INFO] [%s] Connection closed gracefully\n", clientAddr)
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
	// Build prelogin response packet:
	// Fields: VERSION (0x00, 6 bytes), ENCRYPTION (0x01, 1 byte), INSTOPT (0x02, 1 byte), THREADID (0x03, 4 bytes), MARS (0x04, 1 byte)
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

func parseLogin7(payload []byte) (username, password, database string, err error) {
	if len(payload) < 94 {
		return "", "", "", fmt.Errorf("LOGIN7 payload too short (%d bytes)", len(payload))
	}

	uOffset := binary.LittleEndian.Uint16(payload[40:42])
	uLen := binary.LittleEndian.Uint16(payload[42:44])
	pOffset := binary.LittleEndian.Uint16(payload[44:46])
	pLen := binary.LittleEndian.Uint16(payload[46:48])
	dOffset := binary.LittleEndian.Uint16(payload[68:70])
	dLen := binary.LittleEndian.Uint16(payload[70:72])

	if int(uOffset)+int(uLen)*2 <= len(payload) {
		username = ucs22str(payload[uOffset : uOffset+uLen*2])
	}
	if int(pOffset)+int(pLen)*2 <= len(payload) {
		password = unmanglePassword(payload[pOffset : pOffset+pLen*2])
	}
	if int(dOffset)+int(dLen)*2 <= len(payload) {
		database = ucs22str(payload[dOffset : dOffset+dLen*2])
	}

	return username, password, database, nil
}

func extractSQLFromBatch(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	// All-Headers block length
	totalHeadersLen := binary.LittleEndian.Uint32(payload[0:4])
	if int(totalHeadersLen) >= len(payload) {
		return ""
	}
	sqlBytes := payload[totalHeadersLen:]
	return strings.TrimSpace(ucs22str(sqlBytes))
}

// Wrapper to negotiate TLS wrapped inside TDS PRELOGIN packets (MS-TDS 2.2.6.5)
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

	// Read TDS packet wrapping TLS record
	pktType, _, payload, err := readTDSPacket(c.conn)
	if err != nil {
		return 0, err
	}
	if pktType != packPrelogin && pktType != packReply {
		// Handshake completed, switch to direct stream
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
	// Wrap TLS handshake record in TDS PreLogin packet
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
		fmt.Fprintf(os.Stderr, "Usage example:\n")
		fmt.Fprintf(os.Stderr, "  go run cmd/fabric-proxy/main.go \\\n")
		fmt.Fprintf(os.Stderr, "    -listen \":14330\" \\\n")
		fmt.Fprintf(os.Stderr, "    -proxy-user \"looker_user\" \\\n")
		fmt.Fprintf(os.Stderr, "    -proxy-password \"looker_secret\" \\\n")
		fmt.Fprintf(os.Stderr, "    -fabric-host \"<workspace-id>.datawarehouse.fabric.microsoft.com\" \\\n")
		fmt.Fprintf(os.Stderr, "    -fabric-database \"<warehouse_name>\" \\\n")
		fmt.Fprintf(os.Stderr, "    -client-id \"<azure_client_id>\" \\\n")
		fmt.Fprintf(os.Stderr, "    -tenant-id \"<azure_tenant_id>\" \\\n")
		fmt.Fprintf(os.Stderr, "    -client-secret \"<azure_client_secret>\"\n")
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
		fmt.Println("\nShutting down proxy server...")
		server.Stop()
	}()

	if err := server.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Server exited with error: %v\n", err)
		os.Exit(1)
	}
}
