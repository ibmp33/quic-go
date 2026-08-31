package congestion

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

const paperV1RuntimeEnv = "QUIC_GO_PAPER_V1_SENDER_RUNTIME"

var (
	paperV1RuntimeMu    sync.Mutex
	paperV1ProcessStart = time.Now()
)

// writePaperV1Runtime records direct transport-path observations. It is inert
// unless the Paper-v1 server explicitly supplies an append-only report path.
func writePaperV1Runtime(event map[string]any) {
	path := os.Getenv(paperV1RuntimeEnv)
	if path == "" {
		return
	}
	event["schema_version"] = "sender-runtime-v1.0.0"
	event["monotonic_time_ns"] = time.Since(paperV1ProcessStart).Nanoseconds()
	paperV1RuntimeMu.Lock()
	defer paperV1RuntimeMu.Unlock()
	artifact, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	_ = json.NewEncoder(artifact).Encode(event)
	_ = artifact.Close()
}
