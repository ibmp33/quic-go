package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/http3/qlog"
)

var (
	gitCommit = "unknown"
	buildTime = "unknown"
)

// generatePRData returns a deterministic payload for the /bytes/{n} endpoint.
func generatePRData(n int) []byte {
	b := make([]byte, n)
	seed := uint64(1)
	for i := range n {
		seed = seed * 48271 % 2147483647
		b[i] = byte(seed)
	}
	return b
}

func setupHandler(rootDir string) http.Handler {
	mux := http.NewServeMux()
	if rootDir != "" {
		mux.Handle("/", http.FileServer(http.Dir(rootDir)))
	} else {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, "ok\n")
		})
	}

	mux.HandleFunc("/bytes/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s := strings.TrimPrefix(r.URL.Path, "/bytes/")
		n64, err := strconv.ParseInt(s, 10, 64)
		if s == "" || err != nil || n64 <= 0 {
			http.Error(w, "invalid size", http.StatusBadRequest)
			return
		}
		const maxSize int64 = 1 << 30
		if n64 > maxSize {
			http.Error(w, "size too large", http.StatusBadRequest)
			return
		}
		n := int(n64)
		payload := generatePRData(n)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(n))
		if _, err := w.Write(payload); err != nil {
			log.Printf("write /bytes/%d response failed: %v", n, err)
		}
	})
	return mux
}

func main() {
	addr := flag.String("addr", "localhost:6121", "listen address")
	certFile := flag.String("cert", "./testcert/cert.pem", "TLS certificate path")
	keyFile := flag.String("key", "./testcert/priv.key", "TLS private key path")
	qlogDir := flag.String("qlog-dir", "", "directory for qlog output")
	rootDir := flag.String("root", "", "optional static file root directory")
	showVersion := flag.Bool("version", false, "print build information and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("quic-go-server")
		fmt.Printf("commit: %s\n", gitCommit)
		fmt.Printf("build_time: %s\n", buildTime)
		fmt.Println("congestion_control: cubic")
		fmt.Println("initial_congestion_window_packets: 10")
		return
	}

	if *qlogDir != "" {
		if err := os.MkdirAll(*qlogDir, 0o755); err != nil {
			log.Fatalf("create qlog dir: %v", err)
		}
		absDir, err := filepath.Abs(*qlogDir)
		if err != nil {
			log.Fatalf("resolve qlog dir: %v", err)
		}
		if err := os.Setenv("QLOGDIR", absDir); err != nil {
			log.Fatalf("set QLOGDIR: %v", err)
		}
	}

	server := &http3.Server{
		Addr:    *addr,
		Handler: setupHandler(*rootDir),
		QUICConfig: &quic.Config{
			Tracer:            qlog.DefaultConnectionTracer,
			InitialPacketSize: 1200,
		},
	}

	fmt.Printf("listening on https://%s\n", *addr)
	fmt.Printf("cert: %s\n", *certFile)
	fmt.Printf("key:  %s\n", *keyFile)
	if *qlogDir != "" {
		fmt.Printf("qlog dir: %s\n", *qlogDir)
	}
	if *rootDir != "" {
		fmt.Printf("root: %s\n", *rootDir)
	}
	if err := server.ListenAndServeTLS(*certFile, *keyFile); err != nil {
		log.Fatal(err)
	}
}
