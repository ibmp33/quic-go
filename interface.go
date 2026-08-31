package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"slices"
	"time"

	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/qlogwriter"
)

// The StreamID is the ID of a QUIC stream.
type StreamID = protocol.StreamID

// A Version is a QUIC version number.
type Version = protocol.Version

const (
	// Version1 is RFC 9000
	Version1 = protocol.Version1
	// Version2 is RFC 9369
	Version2 = protocol.Version2
)

// ACKPolicyDefinition is the machine-readable description compiled into the
// endpoint. Experiment manifests should record this object verbatim.
type ACKPolicyDefinition struct {
	Name               string         `json:"name"`
	Version            string         `json:"version"`
	Reference          string         `json:"reference"`
	ReferenceCommit    string         `json:"reference_commit"`
	StateScope         string         `json:"state_scope"`
	PacketNumberSpaces map[string]any `json:"packet_number_spaces"`
	Parameters         map[string]any `json:"parameters"`
}

// DescribeACKPolicy returns the parameters actually compiled into this build.
func DescribeACKPolicy(policy ACKPolicy) ACKPolicyDefinition {
	cryptoSpaces := map[string]any{"threshold": 1, "ack_delay_us": 0, "mode": "immediate"}
	switch policy {
	case ACKPolicyNeqoLike:
		return ACKPolicyDefinition{
			Name: ACKPolicyNeqoLikeName, Version: ACKPolicyNeqoLikeVersion,
			Reference:       "https://github.com/mozilla/neqo/blob/e2a2a7459b8b51778b50209251a61fc5ca020893/neqo-transport/src/tracking.rs",
			ReferenceCommit: "e2a2a7459b8b51778b50209251a61fc5ca020893", StateScope: "per-connection-per-packet-number-space",
			PacketNumberSpaces: map[string]any{"initial": cryptoSpaces, "handshake": cryptoSpaces, "application_data": map[string]any{"mode": "application-delayed-ack"}},
			Parameters: map[string]any{
				"initial_threshold": 2, "steady_threshold": 2,
				"threshold_transition": "none", "transition_counter": "none", "transition_boundary": "none",
				"local_max_ack_delay_us":                    20000,
				"rtt_deadline":                              "min(first-pending-ack-eliciting-receive-time+20ms,last-ACK-send-time+smoothed-RTT) when last ACK and SRTT exist",
				"out_of_order_immediate_ack":                "packet-number is not the next in-order application packet number",
				"previously_reported_missing_immediate_ack": true,
				"ecn_ce_additional_immediate_ack":           false,
				"state_reset":                               "new connection creates new trackers; no modeled migration reset within a connection",
				"ack_frequency_override":                    "forbidden in paper-v1",
			},
		}
	case ACKPolicyChromeLike:
		return ACKPolicyDefinition{
			Name: ACKPolicyChromeLikeName, Version: ACKPolicyChromeLikeVersion,
			Reference:       "https://github.com/google/quiche/blob/38097a7a48d5f7d0853ec0ece88269c08283c9c7/quiche/quic/core/quic_received_packet_manager.cc",
			ReferenceCommit: "38097a7a48d5f7d0853ec0ece88269c08283c9c7", StateScope: "per-connection-per-packet-number-space",
			PacketNumberSpaces: map[string]any{"initial": cryptoSpaces, "handshake": cryptoSpaces, "application_data": map[string]any{"initial_state": "initial-ack-every-2", "steady_state": "decimated-ack-every-10"}},
			Parameters: map[string]any{
				"initial_threshold": 2, "steady_threshold": 10,
				"transition_counter":                        "application-data ACK-eliciting packet-number position relative to the least-observed application packet number; not received-packet count or ACK count",
				"transition_boundary":                       "observed_ack_eliciting_pn >= least_observed_application_pn + 100",
				"boundary_packet_uses":                      "new steady state threshold and timer",
				"transition_direction":                      "one-way exactly once per connection",
				"initial_max_ack_delay_us":                  25000,
				"steady_max_ack_delay":                      "max(1ms,min(25ms,minRTT/4))",
				"new_gap_immediate_ack_scope":               "first four received packets in the newest packet-number range after a gap",
				"previously_reported_missing_immediate_ack": false,
				"ecn_ce_immediate_ack":                      "only on transition from non-CE to CE",
				"state_reset":                               "new connection creates new trackers; no modeled migration reset within a connection",
				"ack_frequency_override":                    "forbidden in paper-v1",
			},
		}
	case ACKPolicyFixed10:
		return ACKPolicyDefinition{Name: "synthetic-fixed-ack-10", Version: "1.0.0", StateScope: "per-connection", Parameters: map[string]any{"threshold": 10, "max_ack_delay_us": 25000}}
	default:
		return ACKPolicyDefinition{Name: "synthetic-fixed-ack-2", Version: "1.0.0", StateScope: "per-connection", Parameters: map[string]any{"threshold": 2, "max_ack_delay_us": 25000}}
	}
}

// SupportedVersions returns the support versions, sorted in descending order of preference.
func SupportedVersions() []Version {
	// clone the slice to prevent the caller from modifying the slice
	return slices.Clone(protocol.SupportedVersions)
}

// A ClientToken is a token received by the client.
// It can be used to skip address validation on future connection attempts.
type ClientToken struct {
	data []byte
	rtt  time.Duration
}

type TokenStore interface {
	// Pop searches for a ClientToken associated with the given key.
	// Since tokens are not supposed to be reused, it must remove the token from the cache.
	// It returns nil when no token is found.
	Pop(key string) (token *ClientToken)

	// Put adds a token to the cache with the given key. It might get called
	// multiple times in a connection.
	Put(key string, token *ClientToken)
}

// Err0RTTRejected is the returned from:
//   - Open{Uni}Stream{Sync}
//   - Accept{Uni}Stream
//   - Stream.Read and Stream.Write
//
// when the server rejects a 0-RTT connection attempt.
var Err0RTTRejected = errors.New("0-RTT rejected")

// ErrWouldBlock is returned by [SendStream.TryWriteAll] if the entire slice can't be queued immediately.
var ErrWouldBlock = errors.New("operation would block")

// ErrWriteLimitReached is returned by [SendStream.WriteWithLimit] when its limiter prevents accepting the entire slice.
var ErrWriteLimitReached = errors.New("write limit reached")

// QUICVersionContextKey can be used to find out the QUIC version of a TLS handshake from the
// context returned by tls.Config.ClientInfo.Context.
var QUICVersionContextKey = handshake.QUICVersionContextKey

// StatelessResetKey is a key used to derive stateless reset tokens.
type StatelessResetKey [32]byte

// TokenGeneratorKey is a key used to encrypt session resumption tokens.
type TokenGeneratorKey = handshake.TokenProtectorKey

// A ConnectionID is a QUIC Connection ID, as defined in RFC 9000.
// It is not able to handle QUIC Connection IDs longer than 20 bytes,
// as they are allowed by RFC 8999.
type ConnectionID = protocol.ConnectionID

// ConnectionIDFromBytes interprets b as a [ConnectionID]. It panics if b is
// longer than 20 bytes.
func ConnectionIDFromBytes(b []byte) ConnectionID {
	return protocol.ParseConnectionID(b)
}

// A ConnectionIDGenerator allows the application to take control over the generation of Connection IDs.
// Connection IDs generated by an implementation must be of constant length.
type ConnectionIDGenerator interface {
	// GenerateConnectionID generates a new Connection ID.
	// Generated Connection IDs must be unique and observers should not be able to correlate two Connection IDs.
	GenerateConnectionID() (ConnectionID, error)

	// ConnectionIDLen returns the length of Connection IDs generated by this implementation.
	// Implementations must return constant-length Connection IDs with lengths between 0 and 20 bytes.
	// A length of 0 can only be used when an endpoint doesn't need to multiplex connections during migration.
	ConnectionIDLen() int
}

// ACKPolicy selects the receiver-side ACK generation policy for application data.
// It is intended for controlled experiments. Initial and Handshake packets are
// always acknowledged immediately.
type ACKPolicy uint8

const (
	// ACKPolicyFixed2 uses an ACK threshold of 2 ack-eliciting application data packets.
	ACKPolicyFixed2 ACKPolicy = iota
	// ACKPolicyFixed10 uses an ACK threshold of 10 ack-eliciting application data packets.
	// Apart from the threshold, it uses the same ACK state machine as ACKPolicyFixed2.
	ACKPolicyFixed10
	// ACKPolicyNeqoLike models the receiver ACK state machine documented by the
	// pinned Neqo reference revision. It is not a claim that this endpoint is Firefox.
	ACKPolicyNeqoLike
	// ACKPolicyChromeLike models QUICHE's receiver ACK-decimation state machine
	// at the pinned Chromium reference revision. It is not a claim that this
	// endpoint is Chrome.
	ACKPolicyChromeLike

	// ACKPolicyDefault is kept as an alias for quic-go's default ACK2 policy.
	ACKPolicyDefault = ACKPolicyFixed2
	// ACKPolicyQUICHE is kept as a source-compatible alias for the policy that was
	// previously exposed under this name. New experiment code should use
	// ACKPolicyChromium.
	ACKPolicyNeqo     = ACKPolicyNeqoLike
	ACKPolicyChromium = ACKPolicyChromeLike
	ACKPolicyQUICHE   = ACKPolicyChromeLike
)

const (
	ACKPolicyNeqoLikeName      = "neqo-like-ack"
	ACKPolicyNeqoLikeVersion   = "1.0.0"
	ACKPolicyChromeLikeName    = "chrome-like-ack"
	ACKPolicyChromeLikeVersion = "1.0.0"
)

// ACKPolicyEvent is emitted by the receiver ACK state machine. MonotonicTime
// is measured from construction of this connection's receiver state.
type ACKPolicyEvent struct {
	SchemaVersion                  string              `json:"schema_version"`
	Event                          string              `json:"event"`
	ConnectionID                   string              `json:"connection_id"`
	FlowID                         string              `json:"flow_id"`
	PolicyName                     string              `json:"policy_name"`
	PolicyVersion                  string              `json:"policy_version"`
	PolicySpecSHA256               string              `json:"policy_spec_sha256"`
	EffectiveParameters            map[string]any      `json:"effective_parameters,omitempty"`
	ProcessStartIdentity           string              `json:"process_start_identity,omitempty"`
	PacketNumber                   uint64              `json:"packet_number"`
	PacketNumberSpace              string              `json:"packet_number_space"`
	OldState                       string              `json:"old_state,omitempty"`
	NewState                       string              `json:"new_state,omitempty"`
	PolicyState                    string              `json:"policy_state,omitempty"`
	MonotonicTime                  time.Duration       `json:"monotonic_time_ns"`
	Reason                         string              `json:"reason"`
	Trigger                        string              `json:"trigger_reason,omitempty"`
	ACKBatchSize                   int                 `json:"ack_batch_size,omitempty"`
	NewlyAcknowledgedPacketCount   int                 `json:"newly_acknowledged_packet_count,omitempty"`
	ACKRanges                      []ACKPolicyACKRange `json:"ack_ranges,omitempty"`
	LargestAcknowledged            uint64              `json:"largest_acknowledged"`
	ACKSpacing                     time.Duration       `json:"ack_spacing_ns,omitempty"`
	ACKDelay                       time.Duration       `json:"ack_delay_ns,omitempty"`
	TimerDeadline                  time.Duration       `json:"timer_deadline_ns,omitempty"`
	Threshold                      uint64              `json:"effective_threshold"`
	ReferencePacketNumber          uint64              `json:"reference_packet_number"`
	ObservedPacketNumber           uint64              `json:"observed_packet_number"`
	TransitionBoundaryPacketNumber uint64              `json:"transition_boundary_packet_number"`
	TransitionSequenceNumber       uint64              `json:"transition_sequence_number,omitempty"`
}

// ACKPolicyACKRange is a stable JSON representation of one ACK range.
type ACKPolicyACKRange struct {
	Smallest uint64 `json:"smallest"`
	Largest  uint64 `json:"largest"`
}

// ACKFrequencyMode selects an explicitly versioned ACK_FREQUENCY
// compatibility profile. The zero value disables negotiation and parsing.
type ACKFrequencyMode uint8

const (
	ACKFrequencyDisabled ACKFrequencyMode = iota
	// ACKFrequencyMvfstDraft interoperates with mvfst's legacy draft codepoints:
	// min_ack_delay=0xff04de1a, ACK_FREQUENCY=0xaf and IMMEDIATE_ACK=0xac.
	ACKFrequencyMvfstDraft
)

// ACKFrequencyEvent reports a sender request that was accepted and applied to
// the application-data ACK state machine.
type ACKFrequencyEvent struct {
	ConnectionID         string
	SequenceNumber       uint64
	PacketTolerance      uint64
	RequestedMaxACKDelay time.Duration
	EffectiveMaxACKDelay time.Duration
	ReorderingThreshold  uint64
	ReceivedAt           time.Time
}

// Config contains all configuration data needed for a QUIC server or client.
type Config struct {
	// GetConfigForClient is called for incoming connections.
	// If the error is not nil, the connection attempt is refused.
	GetConfigForClient func(info *ClientInfo) (*Config, error)
	// The QUIC versions that can be negotiated.
	// If not set, it uses all versions available.
	Versions []Version
	// HandshakeIdleTimeout is the idle timeout before completion of the handshake.
	// If we don't receive any packet from the peer within this time, the connection attempt is aborted.
	// Additionally, if the handshake doesn't complete in twice this time, the connection attempt is also aborted.
	// If this value is zero, the timeout is set to 5 seconds.
	HandshakeIdleTimeout time.Duration
	// MaxIdleTimeout is the maximum duration that may pass without any incoming network activity.
	// The actual value for the idle timeout is the minimum of this value and the peer's.
	// This value only applies after the handshake has completed.
	// If the timeout is exceeded, the connection is closed.
	// If this value is zero, the timeout is set to 30 seconds.
	MaxIdleTimeout time.Duration
	// The TokenStore stores tokens received from the server.
	// Tokens are used to skip address validation on future connection attempts.
	// The key used to store tokens is the ServerName from the tls.Config, if set
	// otherwise the token is associated with the server's IP address.
	TokenStore TokenStore
	// InitialStreamReceiveWindow is the initial size of the stream-level flow control window for receiving data.
	// If the application is consuming data quickly enough, the flow control auto-tuning algorithm
	// will increase the window up to MaxStreamReceiveWindow.
	// If this value is zero, it will default to 512 KB.
	// Values larger than the maximum varint (quicvarint.Max) will be clipped to that value.
	InitialStreamReceiveWindow uint64
	// MaxStreamReceiveWindow is the maximum stream-level flow control window for receiving data.
	// If this value is zero, it will default to 6 MB.
	// Values larger than the maximum varint (quicvarint.Max) will be clipped to that value.
	MaxStreamReceiveWindow uint64
	// InitialConnectionReceiveWindow is the initial size of the stream-level flow control window for receiving data.
	// If the application is consuming data quickly enough, the flow control auto-tuning algorithm
	// will increase the window up to MaxConnectionReceiveWindow.
	// If this value is zero, it will default to 512 KB.
	// Values larger than the maximum varint (quicvarint.Max) will be clipped to that value.
	InitialConnectionReceiveWindow uint64
	// MaxConnectionReceiveWindow is the connection-level flow control window for receiving data.
	// If this value is zero, it will default to 15 MB.
	// Values larger than the maximum varint (quicvarint.Max) will be clipped to that value.
	MaxConnectionReceiveWindow uint64
	// AllowConnectionWindowIncrease is called every time the connection flow controller attempts
	// to increase the connection flow control window.
	// If set, the caller can prevent an increase of the window. Typically, it would do so to
	// limit the memory usage.
	// To avoid deadlocks, it is not valid to call other functions on the connection or on streams
	// in this callback.
	AllowConnectionWindowIncrease func(conn *Conn, delta uint64) bool
	// MaxIncomingStreams is the maximum number of concurrent bidirectional streams that a peer is allowed to open.
	// If not set, it will default to 100.
	// If set to a negative value, it doesn't allow any bidirectional streams.
	// Values larger than 2^60 will be clipped to that value.
	MaxIncomingStreams int64
	// MaxIncomingUniStreams is the maximum number of concurrent unidirectional streams that a peer is allowed to open.
	// If not set, it will default to 100.
	// If set to a negative value, it doesn't allow any unidirectional streams.
	// Values larger than 2^60 will be clipped to that value.
	MaxIncomingUniStreams int64
	// KeepAlivePeriod defines whether this peer will periodically send a packet to keep the connection alive.
	// If set to 0, then no keep alive is sent. Otherwise, the keep alive is sent on that period (or at most
	// every half of MaxIdleTimeout, whichever is smaller).
	KeepAlivePeriod time.Duration
	// InitialPacketSize is the initial size (and the lower limit) for packets sent.
	// Under most circumstances, it is not necessary to manually set this value,
	// since path MTU discovery quickly finds the path's MTU.
	// If set too high, the path might not support packets of that size, leading to a timeout of the QUIC handshake.
	// Values below 1200 are invalid.
	InitialPacketSize uint16
	// DisablePathMTUDiscovery disables Path MTU Discovery (RFC 8899).
	// This allows the sending of QUIC packets that fully utilize the available MTU of the path.
	// Path MTU discovery is only available on systems that allow setting of the Don't Fragment (DF) bit.
	DisablePathMTUDiscovery bool
	// Allow0RTT allows the application to decide if a 0-RTT connection attempt should be accepted.
	// Only valid for the server.
	Allow0RTT bool
	// Enable QUIC datagram support (RFC 9221).
	EnableDatagrams bool
	// Enable QUIC Stream Resets with Partial Delivery.
	// See https://datatracker.ietf.org/doc/html/draft-ietf-quic-reliable-stream-reset-09.
	EnableStreamResetPartialDelivery bool

	// ACKPolicy selects the receiver-side ACK policy for application data.
	// The zero value uses quic-go's default behavior.
	ACKPolicy ACKPolicy
	// ACKPolicyEventHandler receives receiver policy transitions and ACK
	// episodes synchronously on the connection event loop.
	ACKPolicyEventHandler func(ACKPolicyEvent)
	// PaperV1Mode rejects ACK_FREQUENCY and IMMEDIATE_ACK frames after recording
	// an ack_frequency_violation event. It never advertises ACK_FREQUENCY support.
	PaperV1Mode                 bool
	ACKPolicyFlowID             string
	ACKPolicySpecSHA256         string
	ACKPolicyEventSchemaVersion string
	ProcessStartIdentity        string

	// ACKFrequencyMode enables an explicit ACK_FREQUENCY compatibility profile.
	ACKFrequencyMode ACKFrequencyMode
	// MinACKDelay is advertised when ACKFrequencyMode is enabled. A zero value
	// defaults to 1ms.
	MinACKDelay time.Duration
	// ACKFrequencyEventHandler is called synchronously on the connection event
	// loop after a newer ACK_FREQUENCY request has been applied.
	ACKFrequencyEventHandler func(ACKFrequencyEvent)

	Tracer func(ctx context.Context, isClient bool, connID ConnectionID) qlogwriter.Trace
}

// ClientInfo contains information about an incoming connection attempt.
type ClientInfo struct {
	// RemoteAddr is the remote address on the Initial packet.
	// Unless AddrVerified is set, the address is not yet verified, and could be a spoofed IP address.
	RemoteAddr net.Addr
	// AddrVerified says if the remote address was verified using QUIC's Retry mechanism.
	// Note that the Retry mechanism costs one network roundtrip,
	// and is not performed unless Transport.MaxUnvalidatedHandshakes is surpassed.
	AddrVerified bool
}

// ConnectionState records basic details about a QUIC connection.
type ConnectionState struct {
	// TLS contains information about the TLS connection state, incl. the tls.ConnectionState.
	TLS tls.ConnectionState
	// SupportsDatagrams indicates support for QUIC datagrams (RFC 9221).
	SupportsDatagrams struct {
		// Remote is true if the peer advertised datagram support.
		// Local is true if datagram support was enabled via Config.EnableDatagrams.
		Remote, Local bool
	}
	// SupportsStreamResetPartialDelivery indicates support for QUIC Stream Resets with Partial Delivery.
	SupportsStreamResetPartialDelivery struct {
		// Remote is true if the peer advertised support.
		// Local is true if support was enabled via Config.EnableStreamResetPartialDelivery.
		Remote, Local bool
	}
	// Used0RTT says if 0-RTT resumption was used.
	Used0RTT bool
	// Version is the QUIC version of the QUIC connection.
	Version Version
	// GSO says if generic segmentation offload is used.
	GSO bool
}
