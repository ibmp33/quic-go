package congestion

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/stretchr/testify/require"
)

func TestPacerWritesDirectPaperV1Observations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sender.jsonl")
	require.NoError(t, os.WriteFile(path, nil, 0o600))
	t.Setenv(paperV1RuntimeEnv, path)
	p := newPacer(func() Bandwidth { return 1_000_000 * BytesPerSecond })
	now := monotime.Now()
	for p.Budget(now) > 0 {
		p.SentPacket(now, initialMaxDatagramSize)
	}
	require.False(t, p.TimeUntilSend().IsZero())

	artifact, err := os.Open(path)
	require.NoError(t, err)
	defer artifact.Close()
	events := map[string]bool{}
	scanner := bufio.NewScanner(artifact)
	for scanner.Scan() {
		var event map[string]any
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &event))
		events[event["event"].(string)] = true
		require.NotZero(t, event["monotonic_time_ns"])
	}
	require.NoError(t, scanner.Err())
	require.True(t, events["pacer_packet_consumed"])
	require.True(t, events["pacing_deadline_computed"])
}
