// Package congestion provides congestion control implementations for RakNet.
//
// RakNet supports two congestion control algorithms:
//   - UDT: A more complex algorithm with receiver-reported arrival rates and
//     packet pair measurements. This is the default for most RakNet applications.
//   - SlidingWindow: A simpler TCP-like slow start and congestion avoidance
//     algorithm. Enabled with USE_SLIDING_WINDOW_CONGESTION_CONTROL=1.
//
// This package provides Go implementations of both algorithms, adapted for
// Minecraft: Bedrock Edition which does not implement the full B/AS exchange
// protocol that native RakNet uses.
package congestion

import "time"

// Controller defines the interface for RakNet congestion control algorithms.
// Both UDT and SlidingWindow implementations satisfy this interface.
type Controller interface {
	// GetTransmissionBandwidth returns how many bytes can be sent for new data.
	// Parameters:
	//   - timeSinceLastTick: Time elapsed since the last call
	//   - unackedBytes: Current number of unacknowledged bytes in flight
	//   - isContinuousSend: Whether we've been continuously sending data
	GetTransmissionBandwidth(timeSinceLastTick time.Duration, unackedBytes int, isContinuousSend bool) int

	// GetRetransmissionBandwidth returns how many bytes can be sent for retransmissions.
	// During slow start this may differ from GetTransmissionBandwidth.
	GetRetransmissionBandwidth(timeSinceLastTick time.Duration, unackedBytes int, isContinuousSend bool) int

	// ShouldSendACKs determines whether ACKs should be sent now based on timing heuristics.
	// Parameters:
	//   - curTime: Current timestamp in milliseconds
	//   - estimatedTimeToNextTick: Expected time in milliseconds until the next tick
	ShouldSendACKs(curTime int64, estimatedTimeToNextTick int64) bool

	// OnQueueACK should be called when an ACK is queued for sending.
	// It tracks the oldest unacknowledged ACK timestamp.
	OnQueueACK(curTime int64)

	// OnSendACK should be called when ACKs are sent.
	// It resets the oldest unacknowledged ACK timestamp.
	OnSendACK()

	// GetRTOForRetransmission returns the retransmission timeout duration.
	// Packets not acknowledged within this duration should be retransmitted.
	GetRTOForRetransmission() time.Duration

	// OnSendBytes must be called for each datagram sent to update internal state.
	// This reduces the available send budget in rate-based mode.
	OnSendBytes(numBytes int)

	// OnDatagramSent should be called when a datagram is sent.
	// Returns the sequence number assigned to the datagram.
	OnDatagramSent() uint32

	// OnAck updates the controller when an ACK is received.
	// Parameters:
	//   - rtt: Round-trip time measurement
	//   - isContinuousSend: Whether we've been continuously sending data
	//   - totalAckedBytes: Cumulative total user-data bytes ACKed
	//   - sequenceNumber: The sequence number being acknowledged
	OnAck(rtt time.Duration, isContinuousSend bool, totalAckedBytes uint64, sequenceNumber uint32)

	// OnNAK is called when a NACK (negative acknowledgement) is received,
	// indicating packet loss detected by the receiver.
	OnNAK()

	// OnResend is called when a timeout-based retransmission is triggered.
	OnResend()

	// IsInSlowStart returns whether the controller is currently in slow start phase.
	IsInSlowStart() bool
}
