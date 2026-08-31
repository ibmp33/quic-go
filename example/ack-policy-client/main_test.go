package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/testdata"
	"github.com/stretchr/testify/require"
)

func TestParseACKPolicy(t *testing.T) {
	testCases := map[string]quic.ACKPolicy{
		"synthetic-fixed-ack-2":  quic.ACKPolicyFixed2,
		"synthetic-fixed-ack-10": quic.ACKPolicyFixed10,
		"neqo-like-ack":          quic.ACKPolicyNeqoLike,
		"chrome-like-ack":        quic.ACKPolicyChromeLike,
	}
	for name, expected := range testCases {
		actual, err := parseACKPolicy(name)
		require.NoError(t, err)
		require.Equal(t, expected, actual)
	}
}

func TestParseApplicationProtocol(t *testing.T) {
	for name, expected := range map[string]applicationProtocol{
		"http":  protocolHTTP3,
		"http3": protocolHTTP3,
		"raw":   protocolRaw,
		"tperf": protocolRaw,
	} {
		actual, err := parseApplicationProtocol(name)
		require.NoError(t, err)
		require.Equal(t, expected, actual)
	}
}

func TestParseApplicationProtocolRejectsUnknownNames(t *testing.T) {
	for _, name := range []string{"", "h3", "quic", "tcp"} {
		_, err := parseApplicationProtocol(name)
		require.EqualError(t, err, "invalid -protocol \""+name+"\"; valid values: http3, raw")
	}
}

func TestRawTransferWriterCountsAndLimitsAcrossWrites(t *testing.T) {
	var destination bytes.Buffer
	var count atomic.Int64
	ctx, cancel := context.WithCancel(context.Background())
	writer := &rawTransferWriter{
		destination: &destination,
		count:       &count,
		maxBytes:    5,
		cancel:      cancel,
	}

	n, err := writer.Write([]byte("abc"))
	require.NoError(t, err)
	require.Equal(t, 3, n)
	n, err = writer.Write([]byte("defg"))
	require.ErrorIs(t, err, errTransferLimitReached)
	require.Equal(t, 2, n)
	require.Equal(t, "abcde", destination.String())
	require.EqualValues(t, 5, count.Load())
	require.True(t, writer.limitReached.Load())
	require.ErrorIs(t, ctx.Err(), context.Canceled)
}

func TestExpectedRawTermination(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	require.True(t, isExpectedRawTermination(nil, ctx, false))
	require.True(t, isExpectedRawTermination(errTransferLimitReached, ctx, false))
	require.False(t, isExpectedRawTermination(errors.New("read failed"), ctx, false))
	cancel()
	require.True(t, isExpectedRawTermination(errors.New("connection closed"), ctx, false))
}

func TestRunRawClientReceivesServerInitiatedUnidirectionalStreams(t *testing.T) {
	serverTLSConf := testdata.GetTLSConfig()
	serverTLSConf.NextProtos = []string{rawALPN}
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLSConf, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, listener.Close()) })

	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			serverErr <- err
			return
		}
		for _, payload := range [][]byte{[]byte("abc"), []byte("defg")} {
			stream, err := conn.OpenUniStreamSync(context.Background())
			if err != nil {
				serverErr <- err
				return
			}
			if _, err := stream.Write(payload); err != nil {
				serverErr <- err
				return
			}
			if err := stream.Close(); err != nil {
				serverErr <- err
				return
			}
		}
		<-conn.Context().Done()
		serverErr <- nil
	}()

	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "raw.bin")
	metricsPath := filepath.Join(tempDir, "metrics.csv")
	err = runRawClient(rawClientConfig{
		addr:    listener.Addr().String(),
		tlsConf: &tls.Config{InsecureSkipVerify: true},
		quicConf: &quic.Config{
			ACKPolicy:        quic.ACKPolicyFixed10,
			ACKFrequencyMode: quic.ACKFrequencyMvfstDraft,
			MinACKDelay:      time.Millisecond,
		},
		duration:      3 * time.Second,
		maxBytes:      7,
		readBuffer:    2,
		metricsPath:   metricsPath,
		outPath:       outputPath,
		ackPolicyName: "synthetic-fixed-ack-10",
	})
	require.NoError(t, err)
	require.NoError(t, <-serverErr)

	output, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	require.Len(t, output, 7)
	metrics, err := os.ReadFile(metricsPath)
	require.NoError(t, err)
	require.Contains(t, string(metrics), "elapsed_ms,cumulative_body_bytes\n")
	require.Contains(t, string(metrics), ",7\n")
}

func TestRunRawClientDurationStopsAnOpenStream(t *testing.T) {
	serverTLSConf := testdata.GetTLSConfig()
	serverTLSConf.NextProtos = []string{rawALPN}
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLSConf, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, listener.Close()) })

	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			serverErr <- err
			return
		}
		stream, err := conn.OpenUniStreamSync(context.Background())
		if err != nil {
			serverErr <- err
			return
		}
		if _, err := stream.Write([]byte("stream stays open")); err != nil {
			serverErr <- err
			return
		}
		<-conn.Context().Done()
		serverErr <- nil
	}()

	start := time.Now()
	err = runRawClient(rawClientConfig{
		addr:          listener.Addr().String(),
		tlsConf:       &tls.Config{InsecureSkipVerify: true},
		quicConf:      &quic.Config{ACKPolicy: quic.ACKPolicyFixed2},
		duration:      200 * time.Millisecond,
		readBuffer:    64,
		metricsPath:   filepath.Join(t.TempDir(), "metrics.csv"),
		ackPolicyName: "synthetic-fixed-ack-2",
	})
	require.NoError(t, err)
	require.Less(t, time.Since(start), 2*time.Second)
	require.NoError(t, <-serverErr)
}

func TestParseACKPolicyRejectsLegacyAndUnknownNames(t *testing.T) {
	for _, name := range []string{"", "default", "quiche", "ack2", "fixed5", "neqo", "chromium", "fixed2", "fixed10"} {
		_, err := parseACKPolicy(name)
		require.EqualError(t, err, "invalid -ack-policy \""+name+"\"; valid values: neqo-like-ack, chrome-like-ack, synthetic-fixed-ack-2, synthetic-fixed-ack-10")
	}
}

func TestParseACKFrequencyMode(t *testing.T) {
	mode, err := parseACKFrequencyMode("disabled")
	require.NoError(t, err)
	require.Equal(t, quic.ACKFrequencyDisabled, mode)

	mode, err = parseACKFrequencyMode("mvfst-draft")
	require.NoError(t, err)
	require.Equal(t, quic.ACKFrequencyMvfstDraft, mode)

	_, err = parseACKFrequencyMode("draft11")
	require.EqualError(t, err, `invalid -ack-frequency-mode "draft11"; valid values: disabled, mvfst-draft`)
}
