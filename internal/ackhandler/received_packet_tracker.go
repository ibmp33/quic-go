package ackhandler

import (
	"fmt"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
)

const reorderingThreshold = 1

type ACKPolicy uint8

const (
	ACKPolicyFixed2 ACKPolicy = iota
	ACKPolicyFixed10
	ACKPolicyNeqoLike
	ACKPolicyChromeLike

	ACKPolicyDefault  = ACKPolicyFixed2
	ACKPolicyNeqo     = ACKPolicyNeqoLike
	ACKPolicyChromium = ACKPolicyChromeLike
	ACKPolicyQUICHE   = ACKPolicyChromeLike
)

const (
	fixed2PacketsBeforeACK              = 2
	fixed10PacketsBeforeACK             = 10
	chromeLikeInitialPacketsBeforeACK   = 2
	chromeLikeDecimatedPacketsBeforeACK = 10
	chromeLikeDecimationThreshold       = 100
	chromeLikeACKDelayRatio             = 0.25
	chromeLikeAlarmGranularity          = time.Millisecond
	neqoPacketsBeforeACK                = 2
	neqoMaxACKDelay                     = 20 * time.Millisecond

	// Compatibility aliases for existing internal tests and downstream branches.
	quicheDecimationThreshold = chromeLikeDecimationThreshold
)

type ACKPolicyEvent struct {
	Event                          string
	PacketNumber                   protocol.PacketNumber
	PacketNumberSpace              string
	OldState                       string
	NewState                       string
	MonotonicTime                  time.Duration
	Reason                         string
	Trigger                        string
	ACKBatchSize                   int
	ACKSpacing                     time.Duration
	ACKDelay                       time.Duration
	Threshold                      uint64
	PolicyState                    string
	NewlyAcknowledgedPacketCount   int
	ACKRanges                      []wire.AckRange
	LargestAcknowledged            protocol.PacketNumber
	TimerDeadline                  time.Duration
	ReferencePacketNumber          protocol.PacketNumber
	ObservedPacketNumber           protocol.PacketNumber
	TransitionBoundaryPacketNumber protocol.PacketNumber
	TransitionSequenceNumber       uint64
}

type ACKPolicyEventHandler func(ACKPolicyEvent)

// The receivedPacketTracker tracks packets for the Initial and Handshake packet number space.
// Every received packet is acknowledged immediately.
type receivedPacketTracker struct {
	ect0, ect1, ecnce uint64

	packetHistory receivedPacketHistory

	lastAck   *wire.AckFrame
	hasNewAck bool // true as soon as we received an ack-eliciting new packet
}

func newReceivedPacketTracker() *receivedPacketTracker {
	return &receivedPacketTracker{packetHistory: *newReceivedPacketHistory()}
}

func (h *receivedPacketTracker) ReceivedPacket(pn protocol.PacketNumber, ecn protocol.ECN, ackEliciting bool) error {
	if isNew := h.packetHistory.ReceivedPacket(pn); !isNew {
		return fmt.Errorf("receivedPacketTracker BUG: ReceivedPacket called for old / duplicate packet %d", pn)
	}

	//nolint:exhaustive // Only need to count ECT(0), ECT(1) and ECN-CE.
	switch ecn {
	case protocol.ECT0:
		h.ect0++
	case protocol.ECT1:
		h.ect1++
	case protocol.ECNCE:
		h.ecnce++
	}
	if !ackEliciting {
		return nil
	}
	h.hasNewAck = true
	return nil
}

func (h *receivedPacketTracker) GetAckFrame() *wire.AckFrame {
	if !h.hasNewAck {
		return nil
	}

	// This function always returns the same ACK frame struct, filled with the most recent values.
	ack := h.lastAck
	if ack == nil {
		ack = &wire.AckFrame{}
	}
	ack.Reset()
	ack.ECT0 = h.ect0
	ack.ECT1 = h.ect1
	ack.ECNCE = h.ecnce
	for r := range h.packetHistory.Backward() {
		ack.AckRanges = append(ack.AckRanges, wire.AckRange{Smallest: r.Start, Largest: r.End})
	}

	h.lastAck = ack
	h.hasNewAck = false
	return ack
}

func (h *receivedPacketTracker) IsPotentiallyDuplicate(pn protocol.PacketNumber) bool {
	return h.packetHistory.IsPotentiallyDuplicate(pn)
}

// The appDataReceivedPacketTracker tracks packets received in the Application Data packet number space.
// It queues ACKs according to the selected packet threshold and delayed-ACK timer.
type appDataReceivedPacketTracker struct {
	receivedPacketTracker

	largestObservedRcvdTime monotime.Time

	largestObserved    protocol.PacketNumber
	hasLargestObserved bool
	firstObserved      protocol.PacketNumber
	hasFirstObserved   bool
	leastObserved      protocol.PacketNumber
	hasLeastObserved   bool
	ignoreBelow        protocol.PacketNumber

	maxAckDelay time.Duration
	ackQueued   bool // true if we need send a new ACK

	ackElicitingPacketsReceivedSinceLastAck int
	packetsReceivedSinceLastAck             int
	ackAlarm                                monotime.Time
	lastAckTime                             monotime.Time
	policyStartTime                         monotime.Time
	policyState                             string
	pendingACKTrigger                       string
	pendingACKPacketNumber                  protocol.PacketNumber
	eventHandler                            ACKPolicyEventHandler
	lastPacketWasCE                         bool
	transitionSequenceNumber                uint64

	policy   ACKPolicy
	rttStats *utils.RTTStats
	logger   utils.Logger

	ackFrequencyOverride ackFrequencyOverride
}

type ackFrequencyOverride struct {
	active              bool
	sequenceNumber      uint64
	packetTolerance     uint64
	maxAckDelay         time.Duration
	reorderingThreshold protocol.PacketNumber
}

func newAppDataReceivedPacketTracker(logger utils.Logger) *appDataReceivedPacketTracker {
	return newAppDataReceivedPacketTrackerWithPolicy(logger, ACKPolicyDefault, nil)
}

func newAppDataReceivedPacketTrackerWithPolicy(logger utils.Logger, policy ACKPolicy, rttStats *utils.RTTStats) *appDataReceivedPacketTracker {
	h := &appDataReceivedPacketTracker{
		receivedPacketTracker: *newReceivedPacketTracker(),
		maxAckDelay:           protocol.MaxAckDelay,
		policy:                policy,
		rttStats:              rttStats,
		logger:                logger,
	}
	if policy == ACKPolicyNeqoLike {
		h.maxAckDelay = neqoMaxACKDelay
	}
	return h
}

func (h *appDataReceivedPacketTracker) ReceivedPacket(pn protocol.PacketNumber, ecn protocol.ECN, rcvTime monotime.Time, ackEliciting bool) error {
	if err := h.receivedPacketTracker.ReceivedPacket(pn, ecn, ackEliciting); err != nil {
		return err
	}
	if h.policyStartTime.IsZero() {
		h.policyStartTime = rcvTime
	}
	if !h.hasFirstObserved {
		h.firstObserved = pn
		h.hasFirstObserved = true
	}
	if !h.hasLeastObserved || pn < h.leastObserved {
		h.leastObserved = pn
		h.hasLeastObserved = true
	}
	h.maybeInitializePolicyState(pn, rcvTime)
	h.packetsReceivedSinceLastAck++
	nextInOrder := protocol.PacketNumber(0)
	if h.hasLargestObserved {
		nextInOrder = h.largestObserved + 1
	}
	// QUIC endpoints randomize their initial packet number. The first observed
	// packet establishes the local ordering baseline and is never reordered
	// merely because its packet number is non-zero.
	outOfOrder := h.hasLargestObserved && pn != nextInOrder
	var reorderingDistance protocol.PacketNumber
	if h.hasLargestObserved && pn > h.largestObserved+1 {
		reorderingDistance = pn - (h.largestObserved + 1)
	}
	if !h.hasLargestObserved || pn >= h.largestObserved {
		h.largestObserved = pn
		h.largestObservedRcvdTime = rcvTime
		h.hasLargestObserved = true
	}
	changedToCE := ecn == protocol.ECNCE && !h.lastPacketWasCE
	h.lastPacketWasCE = ecn == protocol.ECNCE
	if !ackEliciting {
		if !h.ackFrequencyOverride.active && h.policy == ACKPolicyChromeLike && changedToCE {
			h.receivedPacketTracker.hasNewAck = true
			h.ackQueued = true
			h.ackAlarm = 0
			h.pendingACKTrigger = "immediate-ecn-ce"
			h.pendingACKPacketNumber = pn
		}
		return nil
	}
	h.maybeTransitionPolicyState(pn, rcvTime)
	h.ackElicitingPacketsReceivedSinceLastAck++
	isMissing := h.isMissing(pn)
	if queue, trigger := h.shouldQueueACK(pn, changedToCE, isMissing, outOfOrder, reorderingDistance); !h.ackQueued && queue {
		h.ackQueued = true
		h.ackAlarm = 0 // cancel the ack alarm
		h.pendingACKTrigger = trigger
		h.pendingACKPacketNumber = pn
	}
	if !h.ackQueued {
		// No ACK queued, but we'll need to acknowledge the packet after max_ack_delay.
		deadline := rcvTime.Add(h.ackDelay(pn))
		if !h.ackFrequencyOverride.active && h.policy == ACKPolicyNeqoLike && !h.lastAckTime.IsZero() && h.rttStats != nil {
			rttDeadline := h.lastAckTime.Add(h.rttStats.SmoothedRTT())
			if rttDeadline.Before(deadline) {
				deadline = rttDeadline
			}
		}
		if !deadline.After(rcvTime) {
			h.ackQueued = true
			h.ackAlarm = 0
			h.pendingACKTrigger = "timer"
			h.pendingACKPacketNumber = pn
			return nil
		}
		if (!h.ackFrequencyOverride.active && h.isFixedPolicy()) || h.ackAlarm.IsZero() || deadline.Before(h.ackAlarm) {
			h.ackAlarm = deadline
		}
		if h.logger.Debug() {
			h.logger.Debugf("\tSetting ACK timer for policy %d to %s.", h.policy, h.ackAlarm)
		}
	}
	return nil
}

func (h *appDataReceivedPacketTracker) setEventHandler(handler ACKPolicyEventHandler) {
	h.eventHandler = handler
}

func (h *appDataReceivedPacketTracker) emitEvent(event ACKPolicyEvent) {
	if h.eventHandler != nil {
		h.eventHandler(event)
	}
}

func (h *appDataReceivedPacketTracker) elapsed(now monotime.Time) time.Duration {
	if h.policyStartTime.IsZero() {
		return 0
	}
	return max(0, now.Sub(h.policyStartTime))
}

func (h *appDataReceivedPacketTracker) maybeInitializePolicyState(pn protocol.PacketNumber, now monotime.Time) {
	if h.policyState != "" {
		return
	}
	switch h.policy {
	case ACKPolicyNeqoLike:
		h.policyState = "application-delayed-ack"
	case ACKPolicyChromeLike:
		h.policyState = "initial-ack-every-2"
	case ACKPolicyFixed2:
		h.policyState = "synthetic-fixed-2"
	case ACKPolicyFixed10:
		h.policyState = "synthetic-fixed-10"
	}
	h.emitEvent(ACKPolicyEvent{
		Event: "policy_transition", PacketNumber: pn, PacketNumberSpace: "application_data",
		OldState: "uninitialized", NewState: h.policyState, MonotonicTime: h.elapsed(now),
		Reason: "first-packet-in-packet-number-space", Threshold: h.packetsBeforeACK(pn),
	})
}

func (h *appDataReceivedPacketTracker) maybeTransitionPolicyState(pn protocol.PacketNumber, now monotime.Time) {
	if h.policy != ACKPolicyChromeLike || h.policyState != "initial-ack-every-2" || !h.hasLeastObserved {
		return
	}
	// QUICHE enables decimation when the current ACK-instigating packet number
	// is at least peer_first_sending_packet_number + 100. Once enabled it is not
	// reverted if an even lower reordered packet is observed later.
	if pn < h.leastObserved+chromeLikeDecimationThreshold {
		return
	}
	oldState := h.policyState
	h.policyState = "decimated-ack-every-10"
	h.transitionSequenceNumber++
	h.emitEvent(ACKPolicyEvent{
		Event: "policy_transition", PacketNumber: pn, PacketNumberSpace: "application_data",
		OldState: oldState, NewState: h.policyState, MonotonicTime: h.elapsed(now),
		Reason: "packet-number-reached-peer-first-plus-100", Threshold: chromeLikeDecimatedPacketsBeforeACK,
		PolicyState: h.policyState, ReferencePacketNumber: h.leastObserved,
		ObservedPacketNumber:           pn,
		TransitionBoundaryPacketNumber: h.leastObserved + chromeLikeDecimationThreshold,
		TransitionSequenceNumber:       h.transitionSequenceNumber,
	})
}

func (h *appDataReceivedPacketTracker) packetsBeforeACK(pn protocol.PacketNumber) uint64 {
	if h.ackFrequencyOverride.active {
		return h.ackFrequencyOverride.packetTolerance
	}
	switch h.policy {
	case ACKPolicyChromeLike:
		if h.policyState == "decimated-ack-every-10" {
			return chromeLikeDecimatedPacketsBeforeACK
		}
		return chromeLikeInitialPacketsBeforeACK
	case ACKPolicyNeqoLike:
		return neqoPacketsBeforeACK
	case ACKPolicyFixed2:
		return fixed2PacketsBeforeACK
	case ACKPolicyFixed10:
		return fixed10PacketsBeforeACK
	default:
		panic(fmt.Sprintf("invalid ACK policy: %d", h.policy))
	}
}

func (h *appDataReceivedPacketTracker) ackDelay(pn protocol.PacketNumber) time.Duration {
	if h.ackFrequencyOverride.active {
		return h.ackFrequencyOverride.maxAckDelay
	}
	switch h.policy {
	case ACKPolicyChromeLike:
		if h.policyState != "decimated-ack-every-10" || h.rttStats == nil {
			return h.maxAckDelay
		}
		return max(
			chromeLikeAlarmGranularity,
			min(h.maxAckDelay, time.Duration(float64(h.rttStats.MinRTT())*chromeLikeACKDelayRatio)),
		)
	case ACKPolicyNeqoLike:
		return neqoMaxACKDelay
	case ACKPolicyFixed2, ACKPolicyFixed10:
		return h.maxAckDelay
	default:
		panic(fmt.Sprintf("invalid ACK policy: %d", h.policy))
	}
}

func (h *appDataReceivedPacketTracker) isFixedPolicy() bool {
	return h.policy == ACKPolicyFixed2 || h.policy == ACKPolicyFixed10
}

func (h *appDataReceivedPacketTracker) applyAckFrequency(
	sequenceNumber uint64,
	packetTolerance uint64,
	maxAckDelay time.Duration,
	reorderThreshold protocol.PacketNumber,
) bool {
	if h.ackFrequencyOverride.active && sequenceNumber <= h.ackFrequencyOverride.sequenceNumber {
		return false
	}
	h.ackFrequencyOverride = ackFrequencyOverride{
		active:              true,
		sequenceNumber:      sequenceNumber,
		packetTolerance:     packetTolerance,
		maxAckDelay:         maxAckDelay,
		reorderingThreshold: reorderThreshold,
	}
	return true
}

func (h *appDataReceivedPacketTracker) queueImmediateACK() {
	h.ackQueued = true
	h.ackAlarm = 0
	h.pendingACKTrigger = "immediate-ack-frame"
	h.pendingACKPacketNumber = h.largestObserved
}

func (h *appDataReceivedPacketTracker) currentReorderingThreshold() protocol.PacketNumber {
	if h.ackFrequencyOverride.active {
		return h.ackFrequencyOverride.reorderingThreshold
	}
	return reorderingThreshold
}

// IgnoreBelow sets a lower limit for acknowledging packets.
// Packets with packet numbers smaller than p will not be acked.
func (h *appDataReceivedPacketTracker) IgnoreBelow(pn protocol.PacketNumber) {
	if pn <= h.ignoreBelow {
		return
	}
	h.ignoreBelow = pn
	h.packetHistory.DeleteBelow(pn)
	if h.logger.Debug() {
		h.logger.Debugf("\tIgnoring all packets below %d.", pn)
	}
}

// isMissing says if a packet was reported missing in the last ACK.
func (h *appDataReceivedPacketTracker) isMissing(p protocol.PacketNumber) bool {
	if h.lastAck == nil || p < h.ignoreBelow {
		return false
	}
	return p < h.lastAck.LargestAcked() && !h.lastAck.AcksPacket(p)
}

func (h *appDataReceivedPacketTracker) hasNewMissingPackets() bool {
	if h.lastAck == nil {
		return false
	}
	reorderThreshold := h.currentReorderingThreshold()
	if h.largestObserved < reorderThreshold {
		return false
	}
	highestMissing := h.packetHistory.HighestMissingUpTo(h.largestObserved - reorderThreshold)
	if highestMissing == protocol.InvalidPacketNumber {
		return false
	}
	if highestMissing < h.lastAck.LargestAcked() {
		return false
	}
	return highestMissing > h.lastAck.LargestAcked()-reorderThreshold
}

func (h *appDataReceivedPacketTracker) hasChromeLikeNewMissingPackets() bool {
	if len(h.packetHistory.ranges) < 2 {
		return false
	}
	// This mirrors QUICHE's default HasNewMissingPackets rule: acknowledge the
	// first four packets in the newest range after a gap. Missing packet numbers
	// before the peer's least observed packet are not treated as a gap.
	latest := h.packetHistory.ranges[len(h.packetHistory.ranges)-1]
	return latest.End-latest.Start+1 <= 4
}

func (h *appDataReceivedPacketTracker) shouldQueueACK(
	pn protocol.PacketNumber,
	changedToCE bool,
	wasMissing bool,
	outOfOrder bool,
	reorderingDistance protocol.PacketNumber,
) (bool, string) {
	// Send an ACK if this packet was reported missing in an ACK sent before.
	// Ack decimation with reordering relies on the timer to send an ACK, but if
	// missing packets we reported in the previous ACK, send an ACK immediately.
	if !h.ackFrequencyOverride.active &&
		((h.policy == ACKPolicyNeqoLike && (wasMissing || outOfOrder)) ||
			(h.policy != ACKPolicyChromeLike && wasMissing)) {
		if h.logger.Debug() {
			h.logger.Debugf("\tQueueing ACK because packet %d was missing or reordered.", pn)
		}
		return true, "reordering"
	}
	if h.ackFrequencyOverride.active &&
		reorderingDistance > h.ackFrequencyOverride.reorderingThreshold {
		if h.logger.Debug() {
			h.logger.Debugf(
				"\tQueueing ACK because reordering distance %d exceeds threshold %d.",
				reorderingDistance,
				h.ackFrequencyOverride.reorderingThreshold,
			)
		}
		return true, "reordering"
	}

	threshold := h.packetsBeforeACK(pn)
	if uint64(h.ackElicitingPacketsReceivedSinceLastAck) >= threshold {
		if h.logger.Debug() {
			h.logger.Debugf("\tQueueing ACK because %d packets were received after the last ACK (threshold: %d).", h.ackElicitingPacketsReceivedSinceLastAck, threshold)
		}
		return true, "threshold"
	}

	// queue an ACK if there are new missing packets to report
	newMissing := h.hasNewMissingPackets()
	if !h.ackFrequencyOverride.active && h.policy == ACKPolicyChromeLike {
		newMissing = h.hasChromeLikeNewMissingPackets()
	}
	if newMissing {
		h.logger.Debugf("\tQueuing ACK because there's a new missing packet to report.")
		return true, "reordering"
	}

	// queue an ACK if the packet was ECN-CE marked
	if changedToCE && (h.ackFrequencyOverride.active || h.policy != ACKPolicyNeqoLike) {
		h.logger.Debugf("\tQueuing ACK because the packet was ECN-CE marked.")
		return true, "immediate-ecn-ce"
	}
	return false, ""
}

func (h *appDataReceivedPacketTracker) GetAckFrame(now monotime.Time, onlyIfQueued bool) *wire.AckFrame {
	trigger := h.pendingACKTrigger
	if onlyIfQueued && !h.ackQueued {
		if h.ackAlarm.IsZero() || h.ackAlarm.After(now) {
			return nil
		}
		trigger = "timer"
		if h.logger.Debug() && !h.ackAlarm.IsZero() {
			h.logger.Debugf("Sending ACK because the ACK timer expired.")
		}
	}
	ack := h.receivedPacketTracker.GetAckFrame()
	if ack == nil {
		return nil
	}
	ack.DelayTime = max(0, now.Sub(h.largestObservedRcvdTime))
	spacing := time.Duration(0)
	if !h.lastAckTime.IsZero() {
		spacing = max(0, now.Sub(h.lastAckTime))
	}
	if trigger == "" {
		trigger = "opportunistic"
	}
	h.emitEvent(ACKPolicyEvent{
		Event: "ack_episode", PacketNumber: h.largestObserved,
		PacketNumberSpace: "application_data", MonotonicTime: h.elapsed(now),
		Reason: trigger, Trigger: trigger,
		ACKBatchSize:                 h.ackElicitingPacketsReceivedSinceLastAck,
		NewlyAcknowledgedPacketCount: h.packetsReceivedSinceLastAck,
		ACKRanges:                    append([]wire.AckRange(nil), ack.AckRanges...),
		LargestAcknowledged:          ack.LargestAcked(), PolicyState: h.policyState,
		ACKSpacing: spacing, ACKDelay: ack.DelayTime,
		Threshold: h.packetsBeforeACK(h.largestObserved),
		TimerDeadline: func() time.Duration {
			if h.ackAlarm.IsZero() {
				return 0
			}
			return h.elapsed(h.ackAlarm)
		}(),
	})
	h.ackQueued = false
	h.ackAlarm = 0
	h.ackElicitingPacketsReceivedSinceLastAck = 0
	h.packetsReceivedSinceLastAck = 0
	h.lastAckTime = now
	h.pendingACKTrigger = ""
	return ack
}

func (h *appDataReceivedPacketTracker) GetAlarmTimeout() monotime.Time { return h.ackAlarm }
