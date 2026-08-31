package quic

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

func TestPaperV1EventJSONPreservesPacketNumberZero(t *testing.T) {
	encoded, err := json.Marshal(ACKPolicyEvent{
		SchemaVersion:                  "receiver-ack-event-v1.0.0",
		Event:                          "policy_transition",
		ReferencePacketNumber:          0,
		ObservedPacketNumber:           100,
		TransitionBoundaryPacketNumber: 100,
		LargestAcknowledged:            0,
		Threshold:                      10,
		Trigger:                        "threshold",
	})
	require.NoError(t, err)
	var event map[string]any
	require.NoError(t, json.Unmarshal(encoded, &event))
	require.Contains(t, event, "reference_packet_number")
	require.Contains(t, event, "largest_acknowledged")
	require.Equal(t, float64(0), event["reference_packet_number"])
	require.Equal(t, float64(10), event["effective_threshold"])
	require.Equal(t, "threshold", event["trigger_reason"])
}

func TestPaperV1PolicyDefinitionsFreezePinnedReorderingRules(t *testing.T) {
	neqo := DescribeACKPolicy(ACKPolicyNeqoLike)
	chrome := DescribeACKPolicy(ACKPolicyChromeLike)
	require.Equal(t, "e2a2a7459b8b51778b50209251a61fc5ca020893", neqo.ReferenceCommit)
	require.Equal(t, "38097a7a48d5f7d0853ec0ece88269c08283c9c7", chrome.ReferenceCommit)
	require.Equal(t, true, neqo.Parameters["previously_reported_missing_immediate_ack"])
	require.Equal(t, false, chrome.Parameters["previously_reported_missing_immediate_ack"])
	require.Equal(t, "forbidden in paper-v1", chrome.Parameters["ack_frequency_override"])
}

func TestConfigureLocalMvfstACKFrequency(t *testing.T) {
	config := populateConfig(&Config{ACKFrequencyMode: ACKFrequencyMvfstDraft})
	var params wire.TransportParameters
	configureLocalACKFrequency(&params, config)
	require.NotNil(t, params.MinAckDelay)
	require.Equal(t, time.Millisecond, *params.MinAckDelay)
	require.True(t, params.UseMvfstAckFrequency)
}

func TestHandleACKFrequencyAppliesNewSequenceAndReportsEvent(t *testing.T) {
	var events []ACKFrequencyEvent
	config := populateConfig(&Config{
		ACKPolicy:        ACKPolicyNeqo,
		ACKFrequencyMode: ACKFrequencyMvfstDraft,
		MinACKDelay:      2 * time.Millisecond,
		ACKFrequencyEventHandler: func(event ACKFrequencyEvent) {
			events = append(events, event)
		},
	})
	conn := &Conn{config: config, logID: "test-connection"}
	conn.receivedPacketHandler = *ackhandler.NewReceivedPacketHandlerWithPolicy(
		utils.DefaultLogger,
		ackhandler.ACKPolicyNeqo,
		utils.NewRTTStats(),
	)

	frame := &wire.AckFrequencyFrame{
		SequenceNumber:        0,
		AckElicitingThreshold: 4,
		RequestMaxAckDelay:    time.Millisecond,
		ReorderingThreshold:   3,
	}
	require.NoError(t, conn.handleAckFrequencyFrame(frame, protocol.Encryption1RTT))
	require.Len(t, events, 1)
	require.Equal(t, "test-connection", events[0].ConnectionID)
	require.Equal(t, 2*time.Millisecond, events[0].EffectiveMaxACKDelay)

	// A duplicate sequence is ignored and does not emit another applied event.
	frame.AckElicitingThreshold = 2
	require.NoError(t, conn.handleAckFrequencyFrame(frame, protocol.Encryption1RTT))
	require.Len(t, events, 1)

	now := monotime.Now()
	for pn := protocol.PacketNumber(1); pn < 4; pn++ {
		require.NoError(t, conn.receivedPacketHandler.ReceivedPacket(
			pn, protocol.ECNNon, protocol.Encryption1RTT, now, true,
		))
		require.Nil(t, conn.receivedPacketHandler.GetAckFrame(protocol.Encryption1RTT, now, true))
	}
	require.NoError(t, conn.receivedPacketHandler.ReceivedPacket(
		4, protocol.ECNNon, protocol.Encryption1RTT, now, true,
	))
	require.NotNil(t, conn.receivedPacketHandler.GetAckFrame(protocol.Encryption1RTT, now, true))
}

func TestHandleMvfstImmediateACKQueuesACK(t *testing.T) {
	config := populateConfig(&Config{ACKFrequencyMode: ACKFrequencyMvfstDraft})
	conn := &Conn{config: config}
	conn.receivedPacketHandler = *ackhandler.NewReceivedPacketHandler(utils.DefaultLogger)
	now := monotime.Now()
	require.NoError(t, conn.receivedPacketHandler.ReceivedPacket(
		1, protocol.ECNNon, protocol.Encryption1RTT, now, true,
	))
	require.Nil(t, conn.receivedPacketHandler.GetAckFrame(protocol.Encryption1RTT, now, true))
	require.NoError(t, conn.handleImmediateAckFrame(protocol.Encryption1RTT))
	require.NotNil(t, conn.receivedPacketHandler.GetAckFrame(protocol.Encryption1RTT, now, true))
}

func TestACKFrequencyFramesRejectedWhenDisabled(t *testing.T) {
	conn := &Conn{config: populateConfig(&Config{})}
	conn.receivedPacketHandler = *ackhandler.NewReceivedPacketHandler(utils.DefaultLogger)
	err := conn.handleAckFrequencyFrame(&wire.AckFrequencyFrame{
		AckElicitingThreshold: 2,
		ReorderingThreshold:   3,
	}, protocol.Encryption1RTT)
	require.Error(t, err)
	require.Error(t, conn.handleImmediateAckFrame(protocol.Encryption1RTT))
}

func TestPaperV1ACKFrequencyFramesAreLoggedAndRejected(t *testing.T) {
	var events []ACKPolicyEvent
	config := populateConfig(&Config{
		ACKPolicy: ACKPolicyChromeLike, PaperV1Mode: true,
		ACKPolicyFlowID: "flow_b", ACKPolicySpecSHA256: "spec-sha",
		ACKPolicyEventSchemaVersion: "receiver-ack-event-v1.0.0",
		ACKPolicyEventHandler: func(event ACKPolicyEvent) {
			events = append(events, event)
		},
	})
	conn := &Conn{config: config, logID: "connection-b", creationTime: monotime.Now()}
	conn.receivedPacketHandler = *ackhandler.NewReceivedPacketHandler(utils.DefaultLogger)
	err := conn.handleAckFrequencyFrame(&wire.AckFrequencyFrame{
		AckElicitingThreshold: 10, ReorderingThreshold: 3,
	}, protocol.Encryption1RTT)
	require.Error(t, err)
	require.Len(t, events, 1)
	require.Equal(t, "ack_frequency_violation", events[0].Event)
	require.Equal(t, "flow_b", events[0].FlowID)
	require.Equal(t, "spec-sha", events[0].PolicySpecSHA256)
	require.Error(t, conn.handleImmediateAckFrame(protocol.Encryption1RTT))
	require.Len(t, events, 2)
}
