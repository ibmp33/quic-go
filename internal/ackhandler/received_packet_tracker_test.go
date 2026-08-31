package ackhandler

import (
	"fmt"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

func TestReceivedPacketTrackerGenerateACKs(t *testing.T) {
	tracker := newReceivedPacketTracker()

	require.NoError(t, tracker.ReceivedPacket(protocol.PacketNumber(3), protocol.ECNNon, true))
	ack := tracker.GetAckFrame()
	require.NotNil(t, ack)
	require.Equal(t, []wire.AckRange{{Smallest: 3, Largest: 3}}, ack.AckRanges)
	require.Zero(t, ack.DelayTime)

	require.NoError(t, tracker.ReceivedPacket(protocol.PacketNumber(4), protocol.ECNNon, true))
	ack = tracker.GetAckFrame()
	require.NotNil(t, ack)
	require.Equal(t, []wire.AckRange{{Smallest: 3, Largest: 4}}, ack.AckRanges)
	require.Zero(t, ack.DelayTime)

	require.NoError(t, tracker.ReceivedPacket(protocol.PacketNumber(1), protocol.ECNNon, true))
	ack = tracker.GetAckFrame()
	require.NotNil(t, ack)
	require.Equal(t, []wire.AckRange{
		{Smallest: 3, Largest: 4},
		{Smallest: 1, Largest: 1},
	}, ack.AckRanges)
	require.Zero(t, ack.DelayTime)

	// non-ack-eliciting packets don't trigger ACKs
	require.NoError(t, tracker.ReceivedPacket(protocol.PacketNumber(10), protocol.ECNNon, false))
	require.Nil(t, tracker.GetAckFrame())

	require.NoError(t, tracker.ReceivedPacket(protocol.PacketNumber(11), protocol.ECNNon, true))
	ack = tracker.GetAckFrame()
	require.NotNil(t, ack)
	require.Equal(t, []wire.AckRange{
		{Smallest: 10, Largest: 11},
		{Smallest: 3, Largest: 4},
		{Smallest: 1, Largest: 1},
	}, ack.AckRanges)
}

func TestAppDataReceivedPacketTrackerECN(t *testing.T) {
	tr := newAppDataReceivedPacketTracker(utils.DefaultLogger)

	require.NoError(t, tr.ReceivedPacket(0, protocol.ECT0, monotime.Now(), true))
	pn := protocol.PacketNumber(1)
	for range 2 {
		require.NoError(t, tr.ReceivedPacket(pn, protocol.ECT1, monotime.Now(), true))
		pn++
	}
	for range 3 {
		require.NoError(t, tr.ReceivedPacket(pn, protocol.ECNCE, monotime.Now(), true))
		pn++
	}
	ack := tr.GetAckFrame(monotime.Now(), false)
	require.Equal(t, uint64(1), ack.ECT0)
	require.Equal(t, uint64(2), ack.ECT1)
	require.Equal(t, uint64(3), ack.ECNCE)
}

func TestAppDataReceivedPacketTrackerAckEverySecondPacket(t *testing.T) {
	tr := newAppDataReceivedPacketTracker(utils.DefaultLogger)
	require.Nil(t, tr.GetAckFrame(monotime.Now(), true))

	for p := protocol.PacketNumber(1); p <= 20; p++ {
		require.NoError(t, tr.ReceivedPacket(p, protocol.ECNNon, monotime.Now(), true))
		switch p % 2 {
		case 0:
			require.NotNil(t, tr.GetAckFrame(monotime.Now(), true))
		case 1:
			require.Nil(t, tr.GetAckFrame(monotime.Now(), true))
		}
	}
}

func TestFixedACKPoliciesOnlyDifferByPacketThreshold(t *testing.T) {
	testCases := []struct {
		name      string
		policy    ACKPolicy
		threshold protocol.PacketNumber
	}{
		{name: "fixed2", policy: ACKPolicyFixed2, threshold: 2},
		{name: "fixed10", policy: ACKPolicyFixed10, threshold: 10},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tr := newAppDataReceivedPacketTrackerWithPolicy(utils.DefaultLogger, tc.policy, nil)
			now := monotime.Now()
			for pn := protocol.PacketNumber(1); pn < tc.threshold; pn++ {
				require.NoError(t, tr.ReceivedPacket(pn, protocol.ECNNon, now, true))
				require.Nil(t, tr.GetAckFrame(now, true))
			}
			require.NoError(t, tr.ReceivedPacket(tc.threshold, protocol.ECNNon, now, true))
			require.NotNil(t, tr.GetAckFrame(now, true))
			require.Equal(t, protocol.MaxAckDelay, tr.maxAckDelay)
		})
	}
}

func TestAppDataReceivedPacketTrackerQUICHEPolicy(t *testing.T) {
	rttStats := utils.NewRTTStats()
	rttStats.UpdateRTT(8*time.Millisecond, 0)
	tr := newAppDataReceivedPacketTrackerWithPolicy(utils.DefaultLogger, ACKPolicyQUICHE, rttStats)
	now := monotime.Now()

	for p := range protocol.PacketNumber(quicheDecimationThreshold) {
		require.NoError(t, tr.ReceivedPacket(p, protocol.ECNNon, now, true))
		if p%2 == 0 {
			require.Nil(t, tr.GetAckFrame(now, true))
		} else {
			require.NotNil(t, tr.GetAckFrame(now, true))
		}
	}

	for p := protocol.PacketNumber(100); p < 109; p++ {
		rcvTime := now.Add(time.Duration(p-99) * time.Microsecond)
		require.NoError(t, tr.ReceivedPacket(p, protocol.ECNNon, rcvTime, true))
		require.Nil(t, tr.GetAckFrame(rcvTime, true))
	}
	require.Equal(t, now.Add(time.Microsecond).Add(2*time.Millisecond), tr.GetAlarmTimeout())

	require.NoError(t, tr.ReceivedPacket(109, protocol.ECNNon, now.Add(10*time.Microsecond), true))
	require.NotNil(t, tr.GetAckFrame(now.Add(10*time.Microsecond), true))
}

func TestAppDataReceivedPacketTrackerQUICHETimerBounds(t *testing.T) {
	testCases := []struct {
		name     string
		minRTT   time.Duration
		expected time.Duration
	}{
		{name: "clamped to 1ms", minRTT: 2 * time.Millisecond, expected: time.Millisecond},
		{name: "one quarter of min RTT", minRTT: 40 * time.Millisecond, expected: 10 * time.Millisecond},
		{name: "clamped to 25ms", minRTT: 200 * time.Millisecond, expected: 25 * time.Millisecond},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rttStats := utils.NewRTTStats()
			rttStats.UpdateRTT(tc.minRTT, 0)
			tr := newAppDataReceivedPacketTrackerWithPolicy(utils.DefaultLogger, ACKPolicyQUICHE, rttStats)
			now := monotime.Now()

			// The first packet establishes the start of the packet number space.
			require.NoError(t, tr.ReceivedPacket(10, protocol.ECNNon, now, false))
			for pn := protocol.PacketNumber(11); pn < 109; pn++ {
				require.NoError(t, tr.ReceivedPacket(pn, protocol.ECNNon, now, false))
			}
			// Before packet number advancement reaches 100, QUICHE still uses 25ms.
			require.NoError(t, tr.ReceivedPacket(109, protocol.ECNNon, now, true))
			require.Equal(t, now.Add(protocol.MaxAckDelay), tr.GetAlarmTimeout())
			require.NotNil(t, tr.GetAckFrame(now, false))

			rcvTime := now.Add(time.Millisecond)
			require.NoError(t, tr.ReceivedPacket(110, protocol.ECNNon, rcvTime, true))
			require.Equal(t, rcvTime.Add(tc.expected), tr.GetAlarmTimeout())
			require.Nil(t, tr.GetAckFrame(rcvTime.Add(tc.expected-time.Nanosecond), true))
			require.NotNil(t, tr.GetAckFrame(rcvTime.Add(tc.expected), true))
		})
	}
}

func TestAppDataReceivedPacketTrackerNeqoPolicy(t *testing.T) {
	tr := newAppDataReceivedPacketTrackerWithPolicy(utils.DefaultLogger, ACKPolicyNeqo, nil)
	now := monotime.Now()

	require.NoError(t, tr.ReceivedPacket(0, protocol.ECNNon, now, true))
	require.Equal(t, now.Add(neqoMaxACKDelay), tr.GetAlarmTimeout())
	require.Nil(t, tr.GetAckFrame(now, true))

	require.NoError(t, tr.ReceivedPacket(1, protocol.ECNNon, now, true))
	require.NotNil(t, tr.GetAckFrame(now, true))

	require.NoError(t, tr.ReceivedPacket(3, protocol.ECNNon, now, true))
	require.NotNil(t, tr.GetAckFrame(now, true))
	require.NoError(t, tr.ReceivedPacket(2, protocol.ECNNon, now, true))
	require.NotNil(t, tr.GetAckFrame(now, true))
}

func TestAppDataReceivedPacketTrackerNeqoTimerExpiresAt20ms(t *testing.T) {
	tr := newAppDataReceivedPacketTrackerWithPolicy(utils.DefaultLogger, ACKPolicyNeqo, nil)
	now := monotime.Now()

	require.NoError(t, tr.ReceivedPacket(0, protocol.ECNNon, now, true))
	require.Nil(t, tr.GetAckFrame(now.Add(neqoMaxACKDelay-time.Nanosecond), true))
	require.NotNil(t, tr.GetAckFrame(now.Add(neqoMaxACKDelay), true))
}

func TestChromeLikeStateTransitionExactBoundary(t *testing.T) {
	tr := newAppDataReceivedPacketTrackerWithPolicy(utils.DefaultLogger, ACKPolicyChromeLike, nil)
	var events []ACKPolicyEvent
	tr.setEventHandler(func(event ACKPolicyEvent) { events = append(events, event) })
	now := monotime.Now()

	require.NoError(t, tr.ReceivedPacket(10, protocol.ECNNon, now, false))
	require.Equal(t, "initial-ack-every-2", tr.policyState)
	require.Equal(t, uint64(2), tr.packetsBeforeACK(109))
	require.NoError(t, tr.ReceivedPacket(109, protocol.ECNNon, now.Add(time.Millisecond), true))
	require.Equal(t, "initial-ack-every-2", tr.policyState)
	require.NoError(t, tr.ReceivedPacket(110, protocol.ECNNon, now.Add(2*time.Millisecond), true))
	require.Equal(t, "decimated-ack-every-10", tr.policyState)
	require.Equal(t, uint64(10), tr.packetsBeforeACK(110))

	require.Len(t, events, 2)
	require.Equal(t, "uninitialized", events[0].OldState)
	require.Equal(t, "initial-ack-every-2", events[0].NewState)
	require.Equal(t, protocol.PacketNumber(110), events[1].PacketNumber)
	require.Equal(t, "packet-number-reached-peer-first-plus-100", events[1].Reason)
}

func TestChromeLikeBoundaryUsesLeastObservedPacketAndNeverReverts(t *testing.T) {
	tr := newAppDataReceivedPacketTrackerWithPolicy(utils.DefaultLogger, ACKPolicyChromeLike, nil)
	now := monotime.Now()
	require.NoError(t, tr.ReceivedPacket(10, protocol.ECNNon, now, false))
	require.NoError(t, tr.ReceivedPacket(5, protocol.ECNNon, now, false))
	require.NoError(t, tr.ReceivedPacket(104, protocol.ECNNon, now, true))
	require.Equal(t, "initial-ack-every-2", tr.policyState)
	require.NoError(t, tr.ReceivedPacket(105, protocol.ECNNon, now, true))
	require.Equal(t, "decimated-ack-every-10", tr.policyState)
	require.NoError(t, tr.ReceivedPacket(1, protocol.ECNNon, now, false))
	require.Equal(t, "decimated-ack-every-10", tr.policyState)
}

func TestNeqoLikeHasNoAutonomousThresholdTransition(t *testing.T) {
	tr := newAppDataReceivedPacketTrackerWithPolicy(utils.DefaultLogger, ACKPolicyNeqoLike, nil)
	var transitions []ACKPolicyEvent
	tr.setEventHandler(func(event ACKPolicyEvent) {
		if event.Event == "policy_transition" {
			transitions = append(transitions, event)
		}
	})
	now := monotime.Now()
	for pn := protocol.PacketNumber(0); pn <= 200; pn++ {
		require.NoError(t, tr.ReceivedPacket(pn, protocol.ECNNon, now, true))
		_ = tr.GetAckFrame(now, true)
	}
	require.Equal(t, "application-delayed-ack", tr.policyState)
	require.Equal(t, uint64(2), tr.packetsBeforeACK(200))
	require.Len(t, transitions, 1)
}

func TestACKPolicyStateIsIsolatedBetweenConnections(t *testing.T) {
	now := monotime.Now()
	first := newAppDataReceivedPacketTrackerWithPolicy(utils.DefaultLogger, ACKPolicyChromeLike, nil)
	second := newAppDataReceivedPacketTrackerWithPolicy(utils.DefaultLogger, ACKPolicyChromeLike, nil)
	require.NoError(t, first.ReceivedPacket(0, protocol.ECNNon, now, false))
	require.NoError(t, second.ReceivedPacket(0, protocol.ECNNon, now, false))
	require.NoError(t, first.ReceivedPacket(100, protocol.ECNNon, now, true))
	require.Equal(t, "decimated-ack-every-10", first.policyState)
	require.Equal(t, "initial-ack-every-2", second.policyState)
	require.Equal(t, uint64(10), first.packetsBeforeACK(100))
	require.Equal(t, uint64(2), second.packetsBeforeACK(100))
}

func TestACKEpisodeEventsRecordThresholdTimerAndReordering(t *testing.T) {
	tr := newAppDataReceivedPacketTrackerWithPolicy(utils.DefaultLogger, ACKPolicyNeqoLike, nil)
	var episodes []ACKPolicyEvent
	tr.setEventHandler(func(event ACKPolicyEvent) {
		if event.Event == "ack_episode" {
			episodes = append(episodes, event)
		}
	})
	now := monotime.Now()
	require.NoError(t, tr.ReceivedPacket(0, protocol.ECNNon, now, true))
	require.NoError(t, tr.ReceivedPacket(1, protocol.ECNNon, now.Add(time.Millisecond), true))
	require.NotNil(t, tr.GetAckFrame(now.Add(time.Millisecond), true))
	require.Equal(t, "threshold", episodes[0].Trigger)
	require.Equal(t, 2, episodes[0].ACKBatchSize)
	require.Equal(t, uint64(2), episodes[0].Threshold)

	require.NoError(t, tr.ReceivedPacket(2, protocol.ECNNon, now.Add(2*time.Millisecond), true))
	require.NotNil(t, tr.GetAckFrame(now.Add(22*time.Millisecond), true))
	require.Equal(t, "timer", episodes[1].Trigger)
	require.Equal(t, 20*time.Millisecond, episodes[1].ACKDelay)

	require.NoError(t, tr.ReceivedPacket(4, protocol.ECNNon, now.Add(23*time.Millisecond), true))
	require.NotNil(t, tr.GetAckFrame(now.Add(23*time.Millisecond), true))
	require.Equal(t, "reordering", episodes[2].Trigger)
}

func TestChromeLikeNewGapImmediateACKWindow(t *testing.T) {
	tr := newAppDataReceivedPacketTrackerWithPolicy(utils.DefaultLogger, ACKPolicyChromeLike, nil)
	now := monotime.Now()
	for pn := protocol.PacketNumber(0); pn <= 1; pn++ {
		require.NoError(t, tr.ReceivedPacket(pn, protocol.ECNNon, now, true))
	}
	require.NotNil(t, tr.GetAckFrame(now, true))
	for pn := protocol.PacketNumber(3); pn <= 6; pn++ {
		require.NoError(t, tr.ReceivedPacket(pn, protocol.ECNNon, now, true))
		require.NotNil(t, tr.GetAckFrame(now, true), "packet %d is in the first four after the gap", pn)
	}
	require.NoError(t, tr.ReceivedPacket(7, protocol.ECNNon, now, true))
	require.Nil(t, tr.GetAckFrame(now, true))
}

func TestChromeLikeFilledPreviouslyReportedGapIsNotSeparateImmediateACK(t *testing.T) {
	tr := newAppDataReceivedPacketTrackerWithPolicy(utils.DefaultLogger, ACKPolicyChromeLike, nil)
	now := monotime.Now()
	require.NoError(t, tr.ReceivedPacket(0, protocol.ECNNon, now, true))
	require.NoError(t, tr.ReceivedPacket(2, protocol.ECNNon, now, true))
	require.NotNil(t, tr.GetAckFrame(now, true), "newest range after a gap is immediate")
	require.NoError(t, tr.ReceivedPacket(1, protocol.ECNNon, now, true))
	require.Nil(t, tr.GetAckFrame(now, true), "filling the old gap has no separate default QUICHE rule")
}

func TestChromeLikeACKsOnlyOnECNTransitionToCE(t *testing.T) {
	tr := newAppDataReceivedPacketTrackerWithPolicy(utils.DefaultLogger, ACKPolicyChromeLike, nil)
	tr.policyState = "decimated-ack-every-10"
	now := monotime.Now()
	require.NoError(t, tr.ReceivedPacket(0, protocol.ECT0, now, true))
	require.Nil(t, tr.GetAckFrame(now, true))
	require.NoError(t, tr.ReceivedPacket(1, protocol.ECNCE, now, true))
	require.NotNil(t, tr.GetAckFrame(now, true))
	require.NoError(t, tr.ReceivedPacket(2, protocol.ECNCE, now, true))
	require.Nil(t, tr.GetAckFrame(now, true))
}

func TestChromeLikeNonAckElicitingECNTransitionStillQueuesACK(t *testing.T) {
	tr := newAppDataReceivedPacketTrackerWithPolicy(utils.DefaultLogger, ACKPolicyChromeLike, nil)
	now := monotime.Now()
	require.NoError(t, tr.ReceivedPacket(0, protocol.ECT0, now, false))
	require.Nil(t, tr.GetAckFrame(now, true))
	require.NoError(t, tr.ReceivedPacket(1, protocol.ECNCE, now, false))
	require.NotNil(t, tr.GetAckFrame(now, true))
}

func TestNeqoLikeTimerIsCappedByOneRTTSincePreviousACK(t *testing.T) {
	rttStats := utils.NewRTTStats()
	rttStats.UpdateRTT(5*time.Millisecond, 0)
	tr := newAppDataReceivedPacketTrackerWithPolicy(utils.DefaultLogger, ACKPolicyNeqoLike, rttStats)
	var episodes []ACKPolicyEvent
	tr.setEventHandler(func(event ACKPolicyEvent) {
		if event.Event == "ack_episode" {
			episodes = append(episodes, event)
		}
	})
	now := monotime.Now()
	require.NoError(t, tr.ReceivedPacket(0, protocol.ECNNon, now, true))
	require.NoError(t, tr.ReceivedPacket(1, protocol.ECNNon, now, true))
	require.NotNil(t, tr.GetAckFrame(now, true))
	require.NoError(t, tr.ReceivedPacket(2, protocol.ECNNon, now.Add(time.Millisecond), true))
	require.Equal(t, now.Add(5*time.Millisecond), tr.GetAlarmTimeout())
	require.Nil(t, tr.GetAckFrame(now.Add(5*time.Millisecond-time.Nanosecond), true))
	require.NotNil(t, tr.GetAckFrame(now.Add(5*time.Millisecond), true))
	require.Equal(t, "timer", episodes[1].Trigger)
}

func TestACKFrequencyOverrideReplacesPolicyThresholdDelayAndReordering(t *testing.T) {
	for _, policy := range []ACKPolicy{ACKPolicyNeqo, ACKPolicyChromium} {
		t.Run(fmt.Sprintf("policy %d", policy), func(t *testing.T) {
			tr := newAppDataReceivedPacketTrackerWithPolicy(utils.DefaultLogger, policy, utils.NewRTTStats())
			require.True(t, tr.applyAckFrequency(0, 4, 7*time.Millisecond, 9))
			require.False(t, tr.applyAckFrequency(0, 2, time.Millisecond, 1))
			require.False(t, tr.applyAckFrequency(0, 2, time.Millisecond, 1))
			require.Equal(t, uint64(4), tr.packetsBeforeACK(1000))
			require.Equal(t, 7*time.Millisecond, tr.ackDelay(1000))
			require.Equal(t, protocol.PacketNumber(9), tr.currentReorderingThreshold())

			now := monotime.Now()
			for pn := protocol.PacketNumber(1); pn < 4; pn++ {
				require.NoError(t, tr.ReceivedPacket(pn, protocol.ECNNon, now, true))
				require.Nil(t, tr.GetAckFrame(now, true))
			}
			require.NoError(t, tr.ReceivedPacket(4, protocol.ECNNon, now, true))
			require.NotNil(t, tr.GetAckFrame(now, true))

			require.True(t, tr.applyAckFrequency(1, 6, 3*time.Millisecond, 5))
			require.Equal(t, uint64(6), tr.packetsBeforeACK(1000))
			require.Equal(t, 3*time.Millisecond, tr.ackDelay(1000))
		})
	}
}

func TestACKFrequencyOverrideSuppressesNeqoImmediateReordering(t *testing.T) {
	tr := newAppDataReceivedPacketTrackerWithPolicy(utils.DefaultLogger, ACKPolicyNeqo, nil)
	require.True(t, tr.applyAckFrequency(0, 10, 5*time.Millisecond, 3))
	now := monotime.Now()
	require.NoError(t, tr.ReceivedPacket(4, protocol.ECNNon, now, false))
	require.NoError(t, tr.ReceivedPacket(3, protocol.ECNNon, now, true))
	require.Nil(t, tr.GetAckFrame(now, true))
}

func TestACKFrequencyOverrideUsesRequestedForwardReorderingThreshold(t *testing.T) {
	for _, tc := range []struct {
		name      string
		secondPN  protocol.PacketNumber
		queuesACK bool
	}{
		{name: "equal threshold", secondPN: 5, queuesACK: false},
		{name: "exceeds threshold", secondPN: 6, queuesACK: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := newAppDataReceivedPacketTrackerWithPolicy(utils.DefaultLogger, ACKPolicyChromium, nil)
			require.True(t, tr.applyAckFrequency(0, 10, 5*time.Millisecond, 3))
			now := monotime.Now()
			require.NoError(t, tr.ReceivedPacket(1, protocol.ECNNon, now, false))
			require.NoError(t, tr.ReceivedPacket(tc.secondPN, protocol.ECNNon, now, true))
			ack := tr.GetAckFrame(now, true)
			if tc.queuesACK {
				require.NotNil(t, ack)
			} else {
				require.Nil(t, ack)
			}
		})
	}
}

func TestQueueImmediateACKOverridesAlarm(t *testing.T) {
	tr := newAppDataReceivedPacketTracker(utils.DefaultLogger)
	now := monotime.Now()
	require.NoError(t, tr.ReceivedPacket(1, protocol.ECNNon, now, true))
	require.NotZero(t, tr.GetAlarmTimeout())
	tr.queueImmediateACK()
	require.Zero(t, tr.GetAlarmTimeout())
	require.NotNil(t, tr.GetAckFrame(now, true))
}

func TestACKFrequencyOverrideDoesNotPostponeACKAlarm(t *testing.T) {
	tr := newAppDataReceivedPacketTrackerWithPolicy(utils.DefaultLogger, ACKPolicyChromium, nil)
	require.True(t, tr.applyAckFrequency(0, 10, 5*time.Millisecond, 3))
	now := monotime.Now()
	require.NoError(t, tr.ReceivedPacket(1, protocol.ECNNon, now, true))
	require.Equal(t, now.Add(5*time.Millisecond), tr.GetAlarmTimeout())

	require.NoError(t, tr.ReceivedPacket(2, protocol.ECNNon, now.Add(time.Millisecond), true))
	require.Equal(t, now.Add(5*time.Millisecond), tr.GetAlarmTimeout())

	// A newer request with a shorter delay can move the deadline earlier.
	require.True(t, tr.applyAckFrequency(1, 10, time.Millisecond, 3))
	require.NoError(t, tr.ReceivedPacket(3, protocol.ECNNon, now.Add(2*time.Millisecond), true))
	require.Equal(t, now.Add(3*time.Millisecond), tr.GetAlarmTimeout())
}

func TestACKFrequencyOverrideDisablesNeqoRTTDeadline(t *testing.T) {
	rttStats := utils.NewRTTStats()
	rttStats.UpdateRTT(2*time.Millisecond, 0)
	tr := newAppDataReceivedPacketTrackerWithPolicy(utils.DefaultLogger, ACKPolicyNeqo, rttStats)
	require.True(t, tr.applyAckFrequency(0, 10, 8*time.Millisecond, 3))
	now := monotime.Now()
	tr.lastAckTime = now
	rcvTime := now.Add(3 * time.Millisecond)
	require.NoError(t, tr.ReceivedPacket(1, protocol.ECNNon, rcvTime, true))
	require.Nil(t, tr.GetAckFrame(rcvTime, true))
	require.Equal(t, rcvTime.Add(8*time.Millisecond), tr.GetAlarmTimeout())
}

func TestACKPoliciesImmediatelyACKPreviouslyReportedMissingPacket(t *testing.T) {
	for _, policy := range []ACKPolicy{ACKPolicyFixed2, ACKPolicyNeqo} {
		t.Run(fmt.Sprintf("policy %d", policy), func(t *testing.T) {
			tr := newAppDataReceivedPacketTrackerWithPolicy(utils.DefaultLogger, policy, utils.NewRTTStats())
			now := monotime.Now()

			// Packet 2 is missing from the ACK generated for packets 1 and 3.
			require.NoError(t, tr.ReceivedPacket(1, protocol.ECNNon, now, true))
			require.NoError(t, tr.ReceivedPacket(3, protocol.ECNNon, now, true))
			require.NotNil(t, tr.GetAckFrame(now, true))

			// Synthetic fixed-2 retains the legacy behavior; Neqo immediately ACKs
			// this packet because it is not the next in-order packet.
			require.NoError(t, tr.ReceivedPacket(2, protocol.ECNNon, now, true))
			require.NotNil(t, tr.GetAckFrame(now, true))
		})
	}
}

func TestAppDataReceivedPacketTrackerNeqoImmediatelyACKsReordering(t *testing.T) {
	tr := newAppDataReceivedPacketTrackerWithPolicy(utils.DefaultLogger, ACKPolicyNeqo, nil)
	now := monotime.Now()

	// Establish the largest observed packet without incrementing the
	// ACK-eliciting packet counter. This isolates the reordering trigger from
	// the every-second-packet trigger.
	require.NoError(t, tr.ReceivedPacket(4, protocol.ECNNon, now, false))
	require.NoError(t, tr.ReceivedPacket(3, protocol.ECNNon, now, true))
	require.NotNil(t, tr.GetAckFrame(now, true))
}

func TestAppDataReceivedPacketTrackerAlarmTimeout(t *testing.T) {
	tr := newAppDataReceivedPacketTracker(utils.DefaultLogger)

	now := monotime.Now()
	require.NoError(t, tr.ReceivedPacket(1, protocol.ECNNon, now, false))
	require.Nil(t, tr.GetAckFrame(monotime.Now(), true))
	require.Zero(t, tr.GetAlarmTimeout())

	rcvTime := now.Add(10 * time.Millisecond)
	require.NoError(t, tr.ReceivedPacket(2, protocol.ECNNon, rcvTime, true))
	require.Equal(t, rcvTime.Add(protocol.MaxAckDelay), tr.GetAlarmTimeout())
	require.Nil(t, tr.GetAckFrame(monotime.Now(), true))

	// no timeout after the ACK has been dequeued
	require.NotNil(t, tr.GetAckFrame(monotime.Now(), false))
	require.Zero(t, tr.GetAlarmTimeout())
}

func TestAppDataReceivedPacketTrackerQueuesECNCE(t *testing.T) {
	tr := newAppDataReceivedPacketTracker(utils.DefaultLogger)

	require.NoError(t, tr.ReceivedPacket(1, protocol.ECNCE, monotime.Now(), true))
	ack := tr.GetAckFrame(monotime.Now(), true)
	require.NotNil(t, ack)
	require.Equal(t, protocol.PacketNumber(1), ack.LargestAcked())
	require.EqualValues(t, 1, ack.ECNCE)
}

func TestAppDataReceivedPacketTrackerMissingPackets(t *testing.T) {
	tr := newAppDataReceivedPacketTracker(utils.DefaultLogger)

	now := monotime.Now()
	require.NoError(t, tr.ReceivedPacket(0, protocol.ECNNon, now, true))
	require.Nil(t, tr.GetAckFrame(now, true))

	require.NoError(t, tr.ReceivedPacket(5, protocol.ECNNon, now, true))
	ack := tr.GetAckFrame(now, true) // ACK: 0 and 5, missing: 1, 2, 3, 4
	require.NotNil(t, ack)
	require.Equal(t, []wire.AckRange{{Smallest: 5, Largest: 5}, {Smallest: 0, Largest: 0}}, ack.AckRanges)

	// now receive one of the missing packets
	require.NoError(t, tr.ReceivedPacket(3, protocol.ECNNon, now, true))
	ack = tr.GetAckFrame(now, true)
	require.NotNil(t, ack)
	require.Equal(t, []wire.AckRange{
		{Smallest: 5, Largest: 5},
		{Smallest: 3, Largest: 3},
		{Smallest: 0, Largest: 0},
	}, ack.AckRanges)

	require.NoError(t, tr.ReceivedPacket(6, protocol.ECNNon, now, true))
	require.Nil(t, tr.GetAckFrame(now, true))
	require.NoError(t, tr.ReceivedPacket(8, protocol.ECNNon, now, true))
	require.NotNil(t, tr.GetAckFrame(now, true))
}

func TestAppDataReceivedPacketTrackerDelayTime(t *testing.T) {
	tr := newAppDataReceivedPacketTracker(utils.DefaultLogger)

	now := monotime.Now()
	require.NoError(t, tr.ReceivedPacket(1, protocol.ECNNon, now, true))
	require.NoError(t, tr.ReceivedPacket(2, protocol.ECNNon, now.Add(-1337*time.Millisecond), true))
	ack := tr.GetAckFrame(now, true)
	require.NotNil(t, ack)
	require.Equal(t, 1337*time.Millisecond, ack.DelayTime)

	// don't use a negative delay time
	require.NoError(t, tr.ReceivedPacket(3, protocol.ECNNon, now.Add(time.Hour), true))
	ack = tr.GetAckFrame(now, false)
	require.NotNil(t, ack)
	require.Zero(t, ack.DelayTime)
}

func TestAppDataReceivedPacketTrackerIgnoreBelow(t *testing.T) {
	tr := newAppDataReceivedPacketTracker(utils.DefaultLogger)

	tr.IgnoreBelow(4)
	// check that packets below 7 are considered duplicates
	require.True(t, tr.IsPotentiallyDuplicate(3))
	require.False(t, tr.IsPotentiallyDuplicate(4))

	for i := 5; i <= 10; i++ {
		require.NoError(t, tr.ReceivedPacket(protocol.PacketNumber(i), protocol.ECNNon, monotime.Now(), true))
	}
	ack := tr.GetAckFrame(monotime.Now(), true)
	require.NotNil(t, ack)
	require.Equal(t, []wire.AckRange{{Smallest: 5, Largest: 10}}, ack.AckRanges)

	tr.IgnoreBelow(7)

	require.NoError(t, tr.ReceivedPacket(11, protocol.ECNNon, monotime.Now(), true))
	require.NoError(t, tr.ReceivedPacket(12, protocol.ECNNon, monotime.Now(), true))
	ack = tr.GetAckFrame(monotime.Now(), true)
	require.NotNil(t, ack)
	require.Equal(t, []wire.AckRange{{Smallest: 7, Largest: 12}}, ack.AckRanges)

	// make sure that old packets are not accepted
	require.ErrorContains(t,
		tr.ReceivedPacket(4, protocol.ECNNon, monotime.Now(), true),
		"receivedPacketTracker BUG: ReceivedPacket called for old / duplicate packet 4",
	)
}
