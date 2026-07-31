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
	ACKPolicyDefault ACKPolicy = iota
	ACKPolicyQUICHE
	ACKPolicyNeqo
)

const (
	quicheInitialPacketsBeforeACK   = 2
	quicheDecimatedPacketsBeforeACK = 10
	quicheDecimationThreshold       = 100
	quicheACKDelayRatio             = 0.25
	quicheAlarmGranularity          = time.Millisecond
	neqoPacketsBeforeACK            = 2
	neqoMaxACKDelay                 = 20 * time.Millisecond
)

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

// Number of ack-eliciting packets received before sending an ACK.
const packetsBeforeAck = 2

// The appDataReceivedPacketTracker tracks packets received in the Application Data packet number space.
// It waits until at least 2 packets were received before queueing an ACK, or until the max_ack_delay was reached.
type appDataReceivedPacketTracker struct {
	receivedPacketTracker

	largestObservedRcvdTime monotime.Time

	largestObserved    protocol.PacketNumber
	hasLargestObserved bool
	firstObserved      protocol.PacketNumber
	hasFirstObserved   bool
	ignoreBelow        protocol.PacketNumber

	maxAckDelay time.Duration
	ackQueued   bool // true if we need send a new ACK

	ackElicitingPacketsReceivedSinceLastAck int
	ackAlarm                                monotime.Time
	lastAckTime                             monotime.Time

	policy   ACKPolicy
	rttStats *utils.RTTStats
	logger   utils.Logger
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
	if policy == ACKPolicyNeqo {
		h.maxAckDelay = neqoMaxACKDelay
	}
	return h
}

func (h *appDataReceivedPacketTracker) ReceivedPacket(pn protocol.PacketNumber, ecn protocol.ECN, rcvTime monotime.Time, ackEliciting bool) error {
	if err := h.receivedPacketTracker.ReceivedPacket(pn, ecn, ackEliciting); err != nil {
		return err
	}
	if !h.hasFirstObserved {
		h.firstObserved = pn
		h.hasFirstObserved = true
	}
	outOfOrder := h.hasLargestObserved && pn < h.largestObserved
	if !h.hasLargestObserved || pn >= h.largestObserved {
		h.largestObserved = pn
		h.largestObservedRcvdTime = rcvTime
		h.hasLargestObserved = true
	}
	if !ackEliciting {
		return nil
	}
	h.ackElicitingPacketsReceivedSinceLastAck++
	isMissing := h.isMissing(pn)
	if !h.ackQueued && h.shouldQueueACK(pn, ecn, isMissing, outOfOrder) {
		h.ackQueued = true
		h.ackAlarm = 0 // cancel the ack alarm
	}
	if !h.ackQueued {
		// No ACK queued, but we'll need to acknowledge the packet after max_ack_delay.
		deadline := rcvTime.Add(h.ackDelay(pn))
		if h.policy == ACKPolicyNeqo && !h.lastAckTime.IsZero() && h.rttStats != nil {
			rttDeadline := h.lastAckTime.Add(h.rttStats.SmoothedRTT())
			if rttDeadline.Before(deadline) {
				deadline = rttDeadline
			}
		}
		if !deadline.After(rcvTime) {
			h.ackQueued = true
			h.ackAlarm = 0
			return nil
		}
		if h.policy == ACKPolicyDefault || h.ackAlarm.IsZero() || deadline.Before(h.ackAlarm) {
			h.ackAlarm = deadline
		}
		if h.logger.Debug() {
			h.logger.Debugf("\tSetting ACK timer for policy %d to %s.", h.policy, h.ackAlarm)
		}
	}
	return nil
}

func (h *appDataReceivedPacketTracker) packetsBeforeACK(pn protocol.PacketNumber) int {
	switch h.policy {
	case ACKPolicyQUICHE:
		if h.hasFirstObserved && pn >= h.firstObserved+quicheDecimationThreshold {
			return quicheDecimatedPacketsBeforeACK
		}
		return quicheInitialPacketsBeforeACK
	case ACKPolicyNeqo:
		return neqoPacketsBeforeACK
	case ACKPolicyDefault:
		return packetsBeforeAck
	default:
		panic(fmt.Sprintf("invalid ACK policy: %d", h.policy))
	}
}

func (h *appDataReceivedPacketTracker) ackDelay(pn protocol.PacketNumber) time.Duration {
	switch h.policy {
	case ACKPolicyQUICHE:
		if !h.hasFirstObserved || pn < h.firstObserved+quicheDecimationThreshold || h.rttStats == nil {
			return h.maxAckDelay
		}
		return max(
			quicheAlarmGranularity,
			min(h.maxAckDelay, time.Duration(float64(h.rttStats.MinRTT())*quicheACKDelayRatio)),
		)
	case ACKPolicyNeqo:
		return neqoMaxACKDelay
	case ACKPolicyDefault:
		return h.maxAckDelay
	default:
		panic(fmt.Sprintf("invalid ACK policy: %d", h.policy))
	}
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
	if h.largestObserved < reorderingThreshold {
		return false
	}
	highestMissing := h.packetHistory.HighestMissingUpTo(h.largestObserved - reorderingThreshold)
	if highestMissing == protocol.InvalidPacketNumber {
		return false
	}
	if highestMissing < h.lastAck.LargestAcked() {
		// the packet was already reported missing in the last ACK
		return false
	}
	return highestMissing > h.lastAck.LargestAcked()-reorderingThreshold
}

func (h *appDataReceivedPacketTracker) shouldQueueACK(pn protocol.PacketNumber, ecn protocol.ECN, wasMissing, outOfOrder bool) bool {
	// Send an ACK if this packet was reported missing in an ACK sent before.
	// Ack decimation with reordering relies on the timer to send an ACK, but if
	// missing packets we reported in the previous ACK, send an ACK immediately.
	if wasMissing || (h.policy == ACKPolicyNeqo && outOfOrder) {
		if h.logger.Debug() {
			h.logger.Debugf("\tQueueing ACK because packet %d was missing or reordered.", pn)
		}
		return true
	}

	threshold := h.packetsBeforeACK(pn)
	if h.ackElicitingPacketsReceivedSinceLastAck >= threshold {
		if h.logger.Debug() {
			h.logger.Debugf("\tQueueing ACK because %d packets were received after the last ACK (threshold: %d).", h.ackElicitingPacketsReceivedSinceLastAck, threshold)
		}
		return true
	}

	// queue an ACK if there are new missing packets to report
	if h.hasNewMissingPackets() {
		h.logger.Debugf("\tQueuing ACK because there's a new missing packet to report.")
		return true
	}

	// queue an ACK if the packet was ECN-CE marked
	if ecn == protocol.ECNCE && h.policy != ACKPolicyNeqo {
		h.logger.Debugf("\tQueuing ACK because the packet was ECN-CE marked.")
		return true
	}
	return false
}

func (h *appDataReceivedPacketTracker) GetAckFrame(now monotime.Time, onlyIfQueued bool) *wire.AckFrame {
	if onlyIfQueued && !h.ackQueued {
		if h.ackAlarm.IsZero() || h.ackAlarm.After(now) {
			return nil
		}
		if h.logger.Debug() && !h.ackAlarm.IsZero() {
			h.logger.Debugf("Sending ACK because the ACK timer expired.")
		}
	}
	ack := h.receivedPacketTracker.GetAckFrame()
	if ack == nil {
		return nil
	}
	ack.DelayTime = max(0, now.Sub(h.largestObservedRcvdTime))
	h.ackQueued = false
	h.ackAlarm = 0
	h.ackElicitingPacketsReceivedSinceLastAck = 0
	h.lastAckTime = now
	return ack
}

func (h *appDataReceivedPacketTracker) GetAlarmTimeout() monotime.Time { return h.ackAlarm }
