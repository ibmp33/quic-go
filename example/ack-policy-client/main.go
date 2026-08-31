package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/http3/qlog"
)

var (
	gitCommit = "unknown"
	buildTime = "unknown"
)

type applicationProtocol string

const (
	protocolHTTP3 applicationProtocol = "http3"
	protocolRaw   applicationProtocol = "raw"
	rawALPN                           = "quic_test"
)

var errTransferLimitReached = errors.New("transfer byte limit reached")

func main() {
	processStartUnixNS := time.Now().UnixNano()
	protocolName := flag.String("protocol", string(protocolHTTP3), "application protocol: http3 or raw")
	urlStr := flag.String("url", "", "single URL to fetch, e.g. https://127.0.0.1:4433/")
	serverAddr := flag.String("addr", "", "raw QUIC server address, e.g. 127.0.0.1:6666 (required with -protocol raw)")
	ackPolicyName := flag.String("ack-policy", "", "ACK policy: neqo-like-ack, chrome-like-ack, synthetic-fixed-ack-2, or synthetic-fixed-ack-10 (required)")
	ackPolicyLog := flag.String("ack-policy-log", "", "optional JSONL path for ACK policy transitions and ACK episodes")
	paperV1 := flag.Bool("paper-v1", false, "enforce receiver-ack-policy-v1.0.0 and reject negotiated ACK_FREQUENCY")
	flowID := flag.String("flow-id", "", "stable experiment flow ID (required with -paper-v1)")
	policySpecSHA256 := flag.String("policy-spec-sha256", "", "frozen policy parameter-schema SHA256 (required with -paper-v1)")
	ackFrequencyModeName := flag.String("ack-frequency-mode", "disabled", "ACK_FREQUENCY compatibility: disabled or mvfst-draft")
	minACKDelay := flag.Duration("min-ack-delay", time.Millisecond, "min_ack_delay advertised with an enabled ACK_FREQUENCY mode")
	localPort := flag.Int("local-port", 0, "optional fixed local UDP port")
	initialDCIDLength := flag.Int("initial-dcid-length", 0, "fixed client Initial destination CID length (8..20; required with -paper-v1)")
	startAtUnixNS := flag.Int64("start-at-unix-ns", 0, "wait until this Unix timestamp before starting the request")
	startTimeout := flag.Duration("start-timeout", 30*time.Second, "maximum time to wait for -start-at-unix-ns")
	metricsPath := flag.String("metrics", "", "CSV path for cumulative received bytes (required)")
	caPath := flag.String("ca", "", "optional CA certificate path")
	insecure := flag.Bool("insecure", false, "skip certificate verification")
	serverName := flag.String("server-name", "", "optional TLS server name override")
	qlogDir := flag.String("qlog-dir", "", "directory for qlog output")
	keyLogPath := flag.String("keylog", "", "TLS key log path (required with -paper-v1)")
	outPath := flag.String("o", "", "optional output file path")
	duration := flag.Duration("duration", 30*time.Second, "maximum transfer duration")
	legacyTimeout := flag.Duration("timeout", 0, "deprecated alias for -duration")
	maxBytes := flag.Uint64("max-bytes", 0, "maximum payload bytes to read (0 is unlimited)")
	readBuffer := flag.Int("read-buffer", 64<<10, "payload read buffer size")
	showVersion := flag.Bool("version", false, "print build information and exit")
	flag.Parse()

	if *showVersion {
		printVersion()
		return
	}
	protocol, err := parseApplicationProtocol(*protocolName)
	if err != nil {
		log.Fatal(err)
	}
	switch protocol {
	case protocolHTTP3:
		if *urlStr == "" {
			log.Fatal("missing -url with -protocol http3")
		}
	case protocolRaw:
		if *serverAddr == "" {
			log.Fatal("missing -addr with -protocol raw")
		}
	}
	if *ackPolicyName == "" {
		log.Fatal("missing -ack-policy; valid values: neqo-like-ack, chrome-like-ack, synthetic-fixed-ack-2, synthetic-fixed-ack-10")
	}
	if *metricsPath == "" {
		log.Fatal("missing -metrics")
	}
	if *duration <= 0 {
		log.Fatal("-duration must be greater than 0")
	}
	if *legacyTimeout < 0 {
		log.Fatal("-timeout must be greater than 0")
	}
	if *legacyTimeout > 0 {
		*duration = *legacyTimeout
	}
	if *startTimeout <= 0 {
		log.Fatal("-start-timeout must be greater than 0")
	}
	if *localPort < 0 || *localPort > 65535 {
		log.Fatal("-local-port must be between 0 and 65535")
	}
	if *initialDCIDLength != 0 && (*initialDCIDLength < 8 || *initialDCIDLength > 20) {
		log.Fatal("-initial-dcid-length must be between 8 and 20")
	}
	if *paperV1 && *initialDCIDLength == 0 {
		log.Fatal("-paper-v1 requires an explicit -initial-dcid-length for reproducible wire validation")
	}
	if *readBuffer <= 0 {
		log.Fatal("-read-buffer must be greater than 0")
	}
	if *maxBytes > ^uint64(0)>>1 {
		log.Fatal("-max-bytes must not exceed 9223372036854775807")
	}

	if *qlogDir != "" {
		if err := os.MkdirAll(*qlogDir, 0o755); err != nil {
			log.Fatalf("create qlog dir: %v", err)
		}
		if err := os.Setenv("QLOGDIR", *qlogDir); err != nil {
			log.Fatalf("set QLOGDIR: %v", err)
		}
	}

	tlsConf, err := buildTLSConfig(*caPath, *insecure)
	if err != nil {
		log.Fatalf("build TLS config: %v", err)
	}
	tlsConf.ServerName = *serverName
	ackPolicy, err := parseACKPolicy(*ackPolicyName)
	if err != nil {
		log.Fatal(err)
	}

	ackFrequencyMode, err := parseACKFrequencyMode(*ackFrequencyModeName)
	if err != nil {
		log.Fatal(err)
	}
	if ackFrequencyMode != quic.ACKFrequencyDisabled && *minACKDelay <= 0 {
		log.Fatal("-min-ack-delay must be greater than 0 when ACK_FREQUENCY is enabled")
	}
	if *paperV1 {
		if ackPolicy != quic.ACKPolicyNeqoLike && ackPolicy != quic.ACKPolicyChromeLike {
			log.Fatal("-paper-v1 permits only neqo-like-ack and chrome-like-ack")
		}
		if ackFrequencyMode != quic.ACKFrequencyDisabled {
			log.Fatal("-paper-v1 requires -ack-frequency-mode=disabled")
		}
		if *ackPolicyLog == "" || *flowID == "" || *policySpecSHA256 == "" || *keyLogPath == "" {
			log.Fatal("-paper-v1 requires -ack-policy-log, -flow-id, -policy-spec-sha256, and -keylog")
		}
	}
	var keyLogFile *os.File
	if *keyLogPath != "" {
		keyLogFile, err = openKeyLog(*keyLogPath)
		if err != nil {
			log.Fatalf("open TLS key log: %v", err)
		}
		defer keyLogFile.Close()
		tlsConf.KeyLogWriter = keyLogFile
	}
	quicConf := &quic.Config{
		ACKPolicy: ackPolicy, ACKFrequencyMode: ackFrequencyMode,
		PaperV1Mode: *paperV1, ACKPolicyFlowID: *flowID,
		ACKPolicySpecSHA256:         *policySpecSHA256,
		ACKPolicyEventSchemaVersion: "receiver-ack-event-v1.0.0",
		ProcessStartIdentity:        fmt.Sprintf("pid:%d:start_unix_ns:%d", os.Getpid(), processStartUnixNS),
	}
	if *ackPolicyLog != "" {
		handler, closeLog, err := newACKPolicyJSONLHandler(*ackPolicyLog)
		if err != nil {
			log.Fatalf("open ACK policy log: %v", err)
		}
		defer closeLog()
		quicConf.ACKPolicyEventHandler = handler
	}
	if ackFrequencyMode != quic.ACKFrequencyDisabled {
		quicConf.MinACKDelay = *minACKDelay
		quicConf.ACKFrequencyEventHandler = printACKFrequencyApplied
	}
	if *qlogDir != "" {
		quicConf.Tracer = qlog.DefaultConnectionTracer
	}
	printACKPolicyConfiguration(ackPolicy)
	printACKFrequencyConfiguration(*ackFrequencyModeName, quicConf.MinACKDelay)

	if *startAtUnixNS > 0 {
		startAt := time.Unix(0, *startAtUnixNS)
		if delay := time.Until(startAt); delay > 0 {
			if delay > *startTimeout {
				log.Fatalf("scheduled start is %s away, exceeding -start-timeout %s", delay, *startTimeout)
			}
			timer := time.NewTimer(delay)
			<-timer.C
		}
	}

	if protocol == protocolRaw {
		if err := runRawClient(rawClientConfig{
			addr:              *serverAddr,
			tlsConf:           tlsConf,
			quicConf:          quicConf,
			localPort:         *localPort,
			duration:          *duration,
			maxBytes:          *maxBytes,
			readBuffer:        *readBuffer,
			metricsPath:       *metricsPath,
			outPath:           *outPath,
			ackPolicyName:     *ackPolicyName,
			qlogDir:           *qlogDir,
			startAtUnixNS:     *startAtUnixNS,
			initialDCIDLength: *initialDCIDLength,
		}); err != nil {
			log.Fatalf("raw QUIC transfer from %s failed: %v", *serverAddr, err)
		}
		return
	}

	rt := &http3.Transport{
		TLSClientConfig: tlsConf,
		QUICConfig:      quicConf,
	}
	var quicTransport *quic.Transport
	if *localPort != 0 {
		udpConn, err := net.ListenUDP("udp", &net.UDPAddr{Port: *localPort})
		if err != nil {
			log.Fatalf("bind local UDP port %d: %v", *localPort, err)
		}
		quicTransport = &quic.Transport{Conn: udpConn, InitialDestinationConnectionIDLength: *initialDCIDLength}
		rt.Dial = func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			remoteAddr, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				return nil, err
			}
			return quicTransport.Dial(ctx, remoteAddr, tlsCfg, cfg)
		}
		defer quicTransport.Close()
	}
	defer rt.Close()

	client := &http.Client{
		Transport: rt,
		Timeout:   *duration,
	}
	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, *urlStr, nil)
	if err != nil {
		log.Fatalf("new request: %v", err)
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("GET %s failed: %v", *urlStr, err)
	}
	defer resp.Body.Close()

	var bytesReceived atomic.Int64
	stopMetrics, err := startMetricsRecorder(*metricsPath, start, &bytesReceived)
	if err != nil {
		log.Fatalf("start metrics recorder: %v", err)
	}
	defer stopMetrics()

	var destination io.Writer = countingWriter{count: &bytesReceived}
	if *outPath != "" {
		if err := os.MkdirAll(filepath.Dir(*outPath), 0o755); err != nil && filepath.Dir(*outPath) != "." {
			log.Fatalf("create output dir: %v", err)
		}
		f, err := os.Create(*outPath)
		if err != nil {
			log.Fatalf("create output file: %v", err)
		}
		defer f.Close()
		destination = io.MultiWriter(f, destination)
	}
	var source io.Reader = resp.Body
	if *maxBytes > 0 {
		source = io.LimitReader(source, int64(*maxBytes))
	}
	_, copyErr := io.CopyBuffer(destination, source, make([]byte, *readBuffer))
	stopMetrics()
	durationEnded := copyErr != nil && (errors.Is(copyErr, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded))
	if copyErr != nil && !durationEnded {
		log.Fatalf("read response body: %v", copyErr)
	}

	elapsed := time.Since(start)
	n := bytesReceived.Load()

	fmt.Printf("URL: %s\n", *urlStr)
	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("Proto: %s\n", resp.Proto)
	fmt.Printf("Content-Length: %d\n", resp.ContentLength)
	fmt.Printf("ACK policy: %s\n", *ackPolicyName)
	fmt.Printf("Local UDP port: %d\n", *localPort)
	fmt.Printf("Initial DCID length: %d\n", *initialDCIDLength)
	fmt.Printf("Request start Unix ns: %d\n", start.UnixNano())
	if *startAtUnixNS > 0 {
		fmt.Printf("Request start error us: %.3f\n", float64(start.UnixNano()-*startAtUnixNS)/1e3)
	}
	fmt.Printf("Bytes: %d\n", n)
	fmt.Printf("Elapsed: %s\n", elapsed)
	if durationEnded {
		fmt.Println("Transfer ended: request timeout (expected for a duration-limited run)")
	}
	if *outPath != "" {
		fmt.Printf("Saved to: %s\n", *outPath)
	}
	if *qlogDir != "" {
		fmt.Printf("qlog dir: %s\n", *qlogDir)
	}
}

type rawClientConfig struct {
	addr              string
	tlsConf           *tls.Config
	quicConf          *quic.Config
	localPort         int
	duration          time.Duration
	maxBytes          uint64
	readBuffer        int
	metricsPath       string
	outPath           string
	ackPolicyName     string
	qlogDir           string
	startAtUnixNS     int64
	initialDCIDLength int
}

func runRawClient(config rawClientConfig) error {
	ctx, cancel := context.WithTimeout(context.Background(), config.duration)
	defer cancel()

	start := time.Now()
	var bytesReceived atomic.Int64
	stopMetrics, err := startMetricsRecorder(config.metricsPath, start, &bytesReceived)
	if err != nil {
		return fmt.Errorf("start metrics recorder: %w", err)
	}
	defer stopMetrics()

	var output io.Writer = io.Discard
	var outputFile *os.File
	if config.outPath != "" {
		if dir := filepath.Dir(config.outPath); dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("create output dir: %w", err)
			}
		}
		outputFile, err = os.Create(config.outPath)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer outputFile.Close()
		output = outputFile
	}

	rawTLSConf := config.tlsConf.Clone()
	rawTLSConf.NextProtos = []string{rawALPN}

	var conn *quic.Conn
	var quicTransport *quic.Transport
	if config.localPort == 0 {
		conn, err = quic.DialAddr(ctx, config.addr, rawTLSConf, config.quicConf)
	} else {
		udpConn, listenErr := net.ListenUDP("udp", &net.UDPAddr{Port: config.localPort})
		if listenErr != nil {
			return fmt.Errorf("bind local UDP port %d: %w", config.localPort, listenErr)
		}
		quicTransport = &quic.Transport{Conn: udpConn, InitialDestinationConnectionIDLength: config.initialDCIDLength}
		defer quicTransport.Close()
		remoteAddr, resolveErr := net.ResolveUDPAddr("udp", config.addr)
		if resolveErr != nil {
			return fmt.Errorf("resolve raw server address %s: %w", config.addr, resolveErr)
		}
		conn, err = quicTransport.Dial(ctx, remoteAddr, rawTLSConf, config.quicConf)
	}
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.CloseWithError(0, "")

	transferCtx, stopTransfer := context.WithCancel(ctx)
	defer stopTransfer()
	destination := &rawTransferWriter{
		destination: output,
		count:       &bytesReceived,
		maxBytes:    config.maxBytes,
		cancel:      stopTransfer,
	}

	var streams sync.WaitGroup
	streamErrors := make(chan error, 1)
	for {
		stream, acceptErr := conn.AcceptUniStream(transferCtx)
		if acceptErr != nil {
			if !isExpectedRawTermination(acceptErr, transferCtx, destination.limitReached.Load()) {
				select {
				case streamErrors <- fmt.Errorf("accept unidirectional stream: %w", acceptErr):
				default:
				}
			}
			break
		}

		streams.Add(1)
		go func(stream *quic.ReceiveStream) {
			defer streams.Done()
			_, copyErr := io.CopyBuffer(destination, stream, make([]byte, config.readBuffer))
			if !isExpectedRawTermination(copyErr, transferCtx, destination.limitReached.Load()) {
				select {
				case streamErrors <- fmt.Errorf("read unidirectional stream %d: %w", stream.StreamID(), copyErr):
					stopTransfer()
				default:
				}
			}
		}(stream)
	}
	// AcceptUniStream observes transferCtx, but reads on streams don't. Closing the
	// connection makes sure duration and byte limits also unblock active readers.
	_ = conn.CloseWithError(0, "")
	streams.Wait()
	stopMetrics()

	select {
	case streamErr := <-streamErrors:
		return streamErr
	default:
	}

	elapsed := time.Since(start)
	fmt.Printf("Protocol: raw QUIC\n")
	fmt.Printf("Server address: %s\n", config.addr)
	fmt.Printf("ALPN: %s\n", rawALPN)
	fmt.Printf("ACK policy: %s\n", config.ackPolicyName)
	fmt.Printf("Local UDP port: %d\n", config.localPort)
	fmt.Printf("Transfer start Unix ns: %d\n", start.UnixNano())
	if config.startAtUnixNS > 0 {
		fmt.Printf("Transfer start error us: %.3f\n", float64(start.UnixNano()-config.startAtUnixNS)/1e3)
	}
	fmt.Printf("Bytes: %d\n", bytesReceived.Load())
	fmt.Printf("Elapsed: %s\n", elapsed)
	switch {
	case destination.limitReached.Load():
		fmt.Println("Transfer ended: maximum byte count reached")
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		fmt.Println("Transfer ended: duration limit reached")
	default:
		fmt.Println("Transfer ended: peer closed the connection")
	}
	if config.outPath != "" {
		fmt.Printf("Saved to: %s\n", config.outPath)
	}
	if config.qlogDir != "" {
		fmt.Printf("qlog dir: %s\n", config.qlogDir)
	}
	return nil
}

type rawTransferWriter struct {
	mu           sync.Mutex
	destination  io.Writer
	count        *atomic.Int64
	maxBytes     uint64
	cancel       context.CancelFunc
	limitReached atomic.Bool
}

func (w *rawTransferWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.limitReached.Load() {
		return 0, errTransferLimitReached
	}
	if w.maxBytes > 0 {
		remaining := int64(w.maxBytes) - w.count.Load()
		if remaining <= 0 {
			w.reachLimit()
			return 0, errTransferLimitReached
		}
		if int64(len(p)) > remaining {
			p = p[:remaining]
		}
	}

	n, err := w.destination.Write(p)
	w.count.Add(int64(n))
	if err != nil {
		return n, err
	}
	if w.maxBytes > 0 && uint64(w.count.Load()) >= w.maxBytes {
		w.reachLimit()
		return n, errTransferLimitReached
	}
	return n, nil
}

func (w *rawTransferWriter) reachLimit() {
	if w.limitReached.CompareAndSwap(false, true) {
		w.cancel()
	}
}

func isExpectedRawTermination(err error, ctx context.Context, limitReached bool) bool {
	if err == nil || errors.Is(err, errTransferLimitReached) || limitReached {
		return true
	}
	if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var applicationErr *quic.ApplicationError
	return errors.As(err, &applicationErr) && applicationErr.ErrorCode == 0
}

type countingWriter struct {
	count *atomic.Int64
}

func (w countingWriter) Write(p []byte) (int, error) {
	w.count.Add(int64(len(p)))
	return len(p), nil
}

func startMetricsRecorder(path string, start time.Time, count *atomic.Int64) (func(), error) {
	if path == "" {
		return func() {}, nil
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	writer := bufio.NewWriter(f)
	if _, err := writer.WriteString("elapsed_ms,cumulative_body_bytes\n"); err != nil {
		f.Close()
		return nil, err
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case now := <-ticker.C:
				fmt.Fprintf(writer, "%d,%d\n", now.Sub(start).Milliseconds(), count.Load())
			case <-stop:
				fmt.Fprintf(writer, "%d,%d\n", time.Since(start).Milliseconds(), count.Load())
				writer.Flush()
				f.Close()
				return
			}
		}
	}()
	var stopped atomic.Bool
	return func() {
		if stopped.CompareAndSwap(false, true) {
			close(stop)
			<-done
		}
	}, nil
}

func parseACKPolicy(name string) (quic.ACKPolicy, error) {
	switch name {
	case "synthetic-fixed-ack-2":
		return quic.ACKPolicyFixed2, nil
	case "synthetic-fixed-ack-10":
		return quic.ACKPolicyFixed10, nil
	case quic.ACKPolicyNeqoLikeName:
		return quic.ACKPolicyNeqoLike, nil
	case quic.ACKPolicyChromeLikeName:
		return quic.ACKPolicyChromeLike, nil
	default:
		return quic.ACKPolicyFixed2, fmt.Errorf("invalid -ack-policy %q; valid values: neqo-like-ack, chrome-like-ack, synthetic-fixed-ack-2, synthetic-fixed-ack-10", name)
	}
}

func parseACKFrequencyMode(name string) (quic.ACKFrequencyMode, error) {
	switch name {
	case "disabled":
		return quic.ACKFrequencyDisabled, nil
	case "mvfst-draft":
		return quic.ACKFrequencyMvfstDraft, nil
	default:
		return quic.ACKFrequencyDisabled, fmt.Errorf(
			"invalid -ack-frequency-mode %q; valid values: disabled, mvfst-draft",
			name,
		)
	}
}

func parseApplicationProtocol(name string) (applicationProtocol, error) {
	switch name {
	case "http", "http3":
		return protocolHTTP3, nil
	case "raw", "tperf":
		return protocolRaw, nil
	default:
		return "", fmt.Errorf("invalid -protocol %q; valid values: http3, raw", name)
	}
}

func printVersion() {
	fmt.Println("quic-go-policy-client")
	fmt.Printf("commit: %s\n", gitCommit)
	fmt.Printf("build_time: %s\n", buildTime)
	fmt.Println("policies: neqo-like-ack,chrome-like-ack,synthetic-fixed-ack-2,synthetic-fixed-ack-10")
	fmt.Println("protocols: http3,raw")
	fmt.Println("ack_frequency_modes: disabled,mvfst-draft")
}

func printACKFrequencyConfiguration(name string, minACKDelay time.Duration) {
	config := map[string]any{
		"event": "ack_frequency_mode_initialized",
		"mode":  name,
	}
	if name == "mvfst-draft" {
		config["min_ack_delay_us"] = minACKDelay.Microseconds()
		config["min_ack_delay_transport_parameter_id"] = "0xff04de1a"
		config["ack_frequency_frame_type"] = "0xaf"
		config["immediate_ack_frame_type"] = "0xac"
	}
	printJSONEvent(config)
}

func printACKFrequencyApplied(event quic.ACKFrequencyEvent) {
	printJSONEvent(map[string]any{
		"event":                      "ack_frequency_applied",
		"connection_id":              event.ConnectionID,
		"sequence_number":            event.SequenceNumber,
		"packet_tolerance":           event.PacketTolerance,
		"requested_max_ack_delay_us": event.RequestedMaxACKDelay.Microseconds(),
		"effective_max_ack_delay_us": event.EffectiveMaxACKDelay.Microseconds(),
		"reordering_threshold":       event.ReorderingThreshold,
		"received_at_unix_ns":        event.ReceivedAt.UnixNano(),
	})
}

func printJSONEvent(event any) {
	b, err := json.Marshal(event)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(b))
}

func printACKPolicyConfiguration(policy quic.ACKPolicy) {
	printJSONEvent(map[string]any{
		"event":      "ack_policy_initialized",
		"definition": quic.DescribeACKPolicy(policy),
	})
}

func newACKPolicyJSONLHandler(path string) (func(quic.ACKPolicyEvent), func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, nil, err
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	var mu sync.Mutex
	writer := bufio.NewWriterSize(f, 64*1024)
	enc := json.NewEncoder(writer)
	handler := func(event quic.ACKPolicyEvent) {
		mu.Lock()
		defer mu.Unlock()
		if err := enc.Encode(event); err != nil {
			log.Printf("write ACK policy event: %v", err)
			return
		}
		if err := writer.Flush(); err != nil {
			log.Printf("flush ACK policy event: %v", err)
		}
	}
	return handler, func() {
		mu.Lock()
		defer mu.Unlock()
		_ = writer.Flush()
		_ = f.Sync()
		_ = f.Close()
	}, nil
}

func buildTLSConfig(caPath string, insecure bool) (*tls.Config, error) {
	if insecure {
		return &tls.Config{InsecureSkipVerify: true}, nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load system cert pool: %w", err)
	}
	if pool == nil {
		pool = x509.NewCertPool()
	}
	if caPath != "" {
		caPEM, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read CA file %s: %w", caPath, err)
		}
		if ok := pool.AppendCertsFromPEM(caPEM); !ok {
			return nil, fmt.Errorf("append CA PEM failed")
		}
	}
	return &tls.Config{RootCAs: pool}, nil
}

func openKeyLog(path string) (*os.File, error) {
	if path == "" {
		return nil, errors.New("empty key log path")
	}
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
}
