package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/http3/qlog"
)

func main() {
	urlStr := flag.String("url", "", "single URL to fetch, e.g. https://127.0.0.1:4433/")
	ackPolicyName := flag.String("ack-policy", "default", "ACK policy: default, quiche, or neqo")
	localPort := flag.Int("local-port", 0, "optional fixed local UDP port")
	startAtUnixNS := flag.Int64("start-at-unix-ns", 0, "wait until this Unix timestamp before starting the request")
	metricsPath := flag.String("metrics", "", "optional CSV path for cumulative response bytes")
	caPath := flag.String("ca", "", "optional CA certificate path")
	insecure := flag.Bool("insecure", false, "skip certificate verification")
	qlogDir := flag.String("qlog-dir", "", "directory for qlog output")
	outPath := flag.String("o", "", "optional output file path")
	timeout := flag.Duration("timeout", 30*time.Second, "request timeout")
	flag.Parse()

	if *urlStr == "" {
		log.Fatal("missing -url")
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
	ackPolicy, err := parseACKPolicy(*ackPolicyName)
	if err != nil {
		log.Fatal(err)
	}

	quicConf := &quic.Config{ACKPolicy: ackPolicy}
	if *qlogDir != "" {
		quicConf.Tracer = qlog.DefaultConnectionTracer
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
		quicTransport = &quic.Transport{Conn: udpConn}
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
		Timeout:   *timeout,
	}

	if *startAtUnixNS > 0 {
		startAt := time.Unix(0, *startAtUnixNS)
		if delay := time.Until(startAt); delay > 0 {
			timer := time.NewTimer(delay)
			<-timer.C
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
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
	_, copyErr := io.Copy(destination, resp.Body)
	stopMetrics()
	if copyErr != nil && !errors.Is(copyErr, context.DeadlineExceeded) {
		log.Fatalf("read response body: %v", copyErr)
	}

	elapsed := time.Since(start)
	n := bytesReceived.Load()

	fmt.Printf("URL: %s\n", *urlStr)
	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("Proto: %s\n", resp.Proto)
	fmt.Printf("ACK policy: %s\n", *ackPolicyName)
	fmt.Printf("Local UDP port: %d\n", *localPort)
	fmt.Printf("Request start Unix ns: %d\n", start.UnixNano())
	fmt.Printf("Bytes: %d\n", n)
	fmt.Printf("Elapsed: %s\n", elapsed)
	if errors.Is(copyErr, context.DeadlineExceeded) {
		fmt.Println("Transfer ended: request timeout (expected for a duration-limited run)")
	}
	if *outPath != "" {
		fmt.Printf("Saved to: %s\n", *outPath)
	}
	if *qlogDir != "" {
		fmt.Printf("qlog dir: %s\n", *qlogDir)
	}
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
	case "default":
		return quic.ACKPolicyDefault, nil
	case "quiche":
		return quic.ACKPolicyQUICHE, nil
	case "neqo":
		return quic.ACKPolicyNeqo, nil
	default:
		return quic.ACKPolicyDefault, fmt.Errorf("unknown ACK policy %q (want default, quiche, or neqo)", name)
	}
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
