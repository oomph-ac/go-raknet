package congestion

import (
	"time"
)

// UDT is a Go adaptation of RakNet's CCRakNetUDT congestion control.
// It implements a two-phase algorithm:
//   - Slow start: Uses a supportive congestion window (CWND, in datagrams)
//   - Normal: Rate-based control using SND (microseconds per byte)
//
// Reference: CCRakNetUDT.cpp, CCRakNetUDT.h
// Source: https://github.com/facebookarchive/RakNet
//
// Differences from Native RakNet Implementation:
//
//  1. B/AS Exchange (CCRakNetUDT.cpp:549-556, CCRakNetUDT.h:256-258):
//     The original CCRakNetUDT exchanges receiver-side arrival rate (AS) and
//     bandwidth estimate (B) via ACK extensions. The receiver calculates AS using
//     ReceiverCalculateDataArrivalRate() (CCRakNetUDT.cpp:268-310) and sends it
//     back to the sender. Minecraft: Bedrock Edition does not embed B/AS in ACKs, so we
//     estimate AS locally when leaving slow start using CWND and RTT. This means:
//     - We don't have & cannot use the receiver's measured arrival rate
//     - We must exit slow start on CWND threshold OR packet loss (not wait for AS)
//     - SND initialization uses our local estimate instead of receiver-reported AS
//
//  2. Slow Start Exit (CCRakNetUDT.cpp:627-633, 399-403, 421-425):
//     Native code checks if AS != UNDEFINED_TRANSFER_RATE before calling
//     EndSlowStart(). Without B/AS exchange, AS would always be undefined, so
//     we instead use endSlowStartWithEstimatedAS() which estimates AS locally.
//
//  3. Packet Pair Measurements (CCRakNetUDT.cpp:466-472, CCRakNetUDT.h:288-296):
//     Native implementation uses packet pairs to estimate link capacity (B).
//     We omit this as our protocol doesn't support packet pair marking.
type UDT struct {
	// mtuBytes is the effective MTU (payload bytes per datagram).
	// see: CCRakNetUDT.h:316 - MAXIMUM_MTU_INCLUDING_UDP_HEADER
	mtuBytes int

	// cwndMaxThreshold is the maximum CWND in datagrams during slow start.
	// see: CCRakNetUDT.h:319 - CWND_MAX_THRESHOLD
	// see: CCRakNetUDT.cpp:89 - set to RESEND_BUFFER_ARRAY_LENGTH (512)
	cwndMaxThreshold float64

	// synMicros is the update interval in microseconds (10ms default).
	// see: CCRakNetUDT.cpp:33-37 - SYN constant
	// Value is 10000 for CC_TIME_TYPE_BYTES==8 (microseconds)
	synMicros float64

	// Slow Start State

	// cwndDatagrams is the congestion window size in datagrams. Starts at 2.
	// see: CCRakNetUDT.h:200-205 - CWND
	// see: CCRakNetUDT.cpp:27 - CWND_MIN_THRESHOLD=2.0
	cwndDatagrams float64

	// isInSlowStart indicates whether we're currently in slow start phase.
	// see: CCRakNetUDT.h:268 - isInSlowStart
	isInSlowStart bool

	// sndMicrosPerByte is time spacing between bytes (microseconds per byte).
	// Larger SND means slower sending. Only used after slow start.
	// see: CCRakNetUDT.h:193-198 - SND
	// Initialized to 1/DEFAULT_TRANSFER_RATE where DEFAULT_TRANSFER_RATE=0.0036 B/us
	// see: CCRakNetUDT.cpp:92-94, 106-107
	sndMicrosPerByte float64

	// bytesCanSendThisTick is the per-tick byte budget for rate-based sending.
	// see: CCRakNetUDT.h:390 - bytesCanSendThisTick
	bytesCanSendThisTick int

	// lastRtt is the most recent RTT measurement.
	// see: CCRakNetUDT.h:393 - lastRtt
	lastRtt time.Duration

	// minRtt and maxRtt track RTT range for variance estimation.
	// see: CCRakNetUDT.h:233-234 - minRTT, maxRTT
	// Used in GetSenderRTOForACK (CCRakNetUDT.cpp:363-369): RTTVar = maxRTT - minRTT
	minRtt time.Duration
	maxRtt time.Duration

	// lastRttOnIncreaseSendRate is the RTT when we last increased send rate.
	// see: CCRakNetUDT.h:392 - lastRttOnIncreaseSendRate
	// Used for RTO calculation in GetRTOForRetransmission (CCRakNetUDT.cpp:371-393)
	lastRttOnIncreaseSendRate time.Duration

	// nextCongestionControlBlock is the sequence number marking the start of
	// the next congestion control interval.
	// see: CCRakNetUDT.h:395 - nextCongestionControlBlock
	// Used in UpdateWindowSizeAndAckOnAckPerSyn (CCRakNetUDT.cpp:654-657) to ensure
	// we only make rate decisions after sending enough new data.
	nextCongestionControlBlock uint32

	// nextDatagramSequenceNumber is the sequence number for the next outgoing datagram.
	// see: CCRakNetUDT.h:286 - nextDatagramSequenceNumber
	nextDatagramSequenceNumber uint32

	// hadPacketlossThisBlock prevents multiple slowdowns per congestion control block.
	// see: CCRakNetUDT.h:396 - hadPacketlossThisBlock
	hadPacketlossThisBlock bool

	// pingsLastInterval is a sliding window of RTT samples in microseconds.
	// see: CCRakNetUDT.h:397 - pingsLastInterval (DataStructures::Queue<CCTimeType>)
	pingsLastInterval []float64

	// pingsLastIntervalTargetCount is the number of samples to collect before
	// making a slope decision. Set to 33 (should be odd).
	// see: CCRakNetUDT.cpp:648 - static const int intervalSize=33;
	pingsLastIntervalTargetCount int

	// oldestUnsentAck is the timestamp (in milliseconds) of the oldest ACK that
	// has been queued but not yet sent. Zero means no ACKs are pending.
	// see: CCRakNetUDT.h:312-313 - oldestUnsentAck
	// Set when first packet is received after ACK send (CCRakNetUDT.cpp:560-561)
	// Reset to zero when ACKs are sent (CCRakNetUDT.cpp:607)
	oldestUnsentAck int64
}

// NewUDT creates a new UDT congestion controller.
// see: CCRakNetUDT::Init in CCRakNetUDT.cpp:63-119
func NewUDT(mtuBytes int) *UDT {
	// see: CCRakNetUDT.cpp:27
	// CWND_MIN_THRESHOLD=2.0
	const defaultCwndMin = 2.0

	// see: CCRakNetUDT.cpp:89, RakNetDefines.h:93
	// CWND_MAX_THRESHOLD=RESEND_BUFFER_ARRAY_LENGTH (512)
	const defaultCwndMaxThresh = 512.0

	// see: CCRakNetUDT.cpp:33-37
	// SYN=10000 for CC_TIME_TYPE_BYTES==8 (microseconds)
	const synUs = 10000.0

	// see: CCRakNetUDT.cpp:92-94
	// DEFAULT_TRANSFER_RATE = 0.0036 BytesPerMicrosecond for 8-byte time type
	// see: CCRakNetUDT.cpp:106-107
	// DEFAULT_BYTE_INTERVAL = 1.0 / 0.0036 ≈ 277.78 microseconds per byte
	const defaultTransferRateBPerUs = 0.0036
	defaultByteIntervalUs := 1.0 / defaultTransferRateBPerUs

	return &UDT{
		mtuBytes:         mtuBytes,
		cwndMaxThreshold: defaultCwndMaxThresh,
		synMicros:        synUs,

		// see: CCRakNetUDT.cpp:82 - CWND=CWND_MIN_THRESHOLD
		cwndDatagrams: defaultCwndMin,

		// see: CCRakNetUDT.cpp:73 - isInSlowStart=true
		isInSlowStart: true,

		// see: CCRakNetUDT.cpp:107 - SND=DEFAULT_BYTE_INTERVAL
		sndMicrosPerByte: defaultByteIntervalUs,

		// see: CCRakNetUDT.cpp:116 - bytesCanSendThisTick=0
		bytesCanSendThisTick: 0,

		// see: CCRakNetUDT.cpp:96-100 - lastRttOnIncreaseSendRate=1000000 (1 second)
		lastRttOnIncreaseSendRate: time.Second,

		// Initialize min/max RTT to zero (will be set on first RTT measurement)
		minRtt: 0,
		maxRtt: 0,

		// see: CCRakNetUDT.cpp:101-102
		nextCongestionControlBlock: 0,
		nextDatagramSequenceNumber: 0,

		// see: CCRakNetUDT.cpp:117
		hadPacketlossThisBlock: false,

		// see: CCRakNetUDT.cpp:118
		pingsLastInterval:            make([]float64, 0, 33),
		pingsLastIntervalTargetCount: 33,
	}
}

// GetTransmissionBandwidth computes how many bytes can be sent now for new data.
// see: CCRakNetUDT::GetTransmissionBandwidth in CCRakNetUDT.cpp:180-204
//
// During slow start: returns CWND*MTU - unackedBytes (lower-bounded at 0)
// Post slow start: returns internal byte budget that refills with elapsed time
//
// Note: Go implementation adds underflow protection (limit < 0 check) which the
// native code lacks. Native code returns uint32_t which could wrap on underflow.
func (c *UDT) GetTransmissionBandwidth(timeSinceLastTick time.Duration, unackedBytes int, isContinuousSend bool) int {
	// see: CCRakNetUDT.cpp:184-188
	if c.isInSlowStart {
		limit := int(c.cwndDatagrams*float64(c.mtuBytes)) - unackedBytes
		if limit < 0 {
			return 0
		}
		return limit
	}

	// see: CCRakNetUDT.cpp:189-190
	// Reset budget before recalculating, matching reference behavior.
	if c.bytesCanSendThisTick > 0 {
		c.bytesCanSendThisTick = 0
	}

	// see: CCRakNetUDT.cpp:192-198
	// Cap timeSinceLastTick to 100ms (100000us) when not continuously sending.
	// This prevents huge bursts after idle periods.
	elapsed := timeSinceLastTick
	if !isContinuousSend && elapsed > 100*time.Millisecond {
		elapsed = 100 * time.Millisecond
	}

	// see: CCRakNetUDT.cpp:200
	// Rate-based: bytesCanSendThisTick = timeSinceLastTick * (1.0/SND)
	if elapsed > 0 {
		elapsedUs := float64(elapsed.Microseconds())
		if c.sndMicrosPerByte > 0 {
			c.bytesCanSendThisTick = int(elapsedUs / c.sndMicrosPerByte)
		}
	}

	// see: CCRakNetUDT.cpp:201-203
	if c.bytesCanSendThisTick > 0 {
		return c.bytesCanSendThisTick
	}
	return 0
}

// GetRetransmissionBandwidth computes how many bytes can be sent for retransmissions.
// see: CCRakNetUDT::GetRetransmissionBandwidth in CCRakNetUDT.cpp:168-178
//
// Key difference from GetTransmissionBandwidth: During slow start, this returns
// the full CWND*MTU without subtracting unackedBytes. This prevents retransmission
// starvation when the window is full.
func (c *UDT) GetRetransmissionBandwidth(timeSinceLastTick time.Duration, unackedBytes int, isContinuousSend bool) int {
	// see: CCRakNetUDT.cpp:172-176
	// During slow start, allow full CWND for retransmissions (don't subtract unacked)
	if c.isInSlowStart {
		return int(c.cwndDatagrams * float64(c.mtuBytes))
	}

	// see: CCRakNetUDT.cpp:177
	// Post slow start, use the same rate-based calculation as regular transmission
	return c.GetTransmissionBandwidth(timeSinceLastTick, unackedBytes, isContinuousSend)
}

// ShouldSendACKs determines whether ACKs should be sent now.
// see: CCRakNetUDT::ShouldSendACKs in CCRakNetUDT.cpp:216-236
//
// The function uses timing heuristics to decide when to flush ACKs:
//  1. If RTT is unknown (RTO unset), send ACKs immediately to help establish timing
//  2. At least one ACK should be sent per SYN interval (10ms) for protocol efficiency
//  3. ACKs should arrive before the remote system would retransmit
//
// Parameters:
//   - curTime: Current timestamp in milliseconds
//   - estimatedTimeToNextTick: Expected time in milliseconds until the next tick
func (c *UDT) ShouldSendACKs(curTime int64, estimatedTimeToNextTick int64) bool {
	// see: CCRakNetUDT.cpp:218
	rto := c.getSenderRTOForACK()

	// see: CCRakNetUDT.cpp:221-225
	// If RTO is unset (RTT unknown), we don't know when the remote will retransmit,
	// so send ACKs immediately to be safe.
	if rto == 0 {
		return true
	}

	// see: CCRakNetUDT.cpp:234-235
	// Simplified equation from the original commented-out version.
	// Two conditions for sending ACKs:
	// 1. curTime >= oldestUnsentAck + SYN: At least one ACK per SYN interval
	// 2. estimatedTimeToNextTick + curTime < oldestUnsentAck + rto - RTT:
	//    ACK will arrive before remote retransmits

	// If no ACKs are pending (oldestUnsentAck is zero), no need to send.
	if c.oldestUnsentAck == 0 {
		return false
	}

	// SYN in milliseconds (synMicros is 10000us = 10ms)
	synMs := int64(c.synMicros / 1000)

	// Condition 1: At least one ACK should be sent per SYN interval.
	// see: CCRakNetUDT.cpp:234 comment: "GU: At least one ACK should be sent per SYN,
	// otherwise your protocol will increase slower."
	if curTime >= c.oldestUnsentAck+synMs {
		return true
	}

	// Condition 2: Check if delaying would cause the ACK to arrive too late.
	// ACK arrival time if we delay: curTime + estimatedTimeToNextTick + RTT/2 (one-way)
	// Remote retransmit time: oldestUnsentAck + rto
	// We want: ackArrivalTime < remoteRetransmitTime
	// Simplified: estimatedTimeToNextTick + curTime < oldestUnsentAck + rto - RTT
	rtoMs := rto.Milliseconds()
	rttMs := c.lastRtt.Milliseconds()
	return estimatedTimeToNextTick+curTime < c.oldestUnsentAck+rtoMs-rttMs
}

// OnQueueACK should be called when an ACK is queued for sending.
// It sets oldestUnsentAck if this is the first ACK queued since the last send.
// see: CCRakNetUDT::OnAck in CCRakNetUDT.cpp:560-561
//
// Parameters:
//   - curTime: Current timestamp in milliseconds
func (c *UDT) OnQueueACK(curTime int64) {
	if c.oldestUnsentAck == 0 {
		c.oldestUnsentAck = curTime
	}
}

// OnSendACK should be called when ACKs are sent.
// It resets oldestUnsentAck to indicate no pending ACKs.
// see: CCRakNetUDT::OnSendAck in CCRakNetUDT.cpp:607
func (c *UDT) OnSendACK() {
	c.oldestUnsentAck = 0
}

// GetRTOForRetransmission returns the retransmission timeout.
// see: CCRakNetUDT::GetRTOForRetransmission in CCRakNetUDT.cpp:371-393
//
// Returns timeout based on lastRttOnIncreaseSendRate * 2, clamped between
// 100ms (minThreshold) and 1000ms (maxThreshold).
func (c *UDT) GetRTOForRetransmission() time.Duration {
	// see: CCRakNetUDT.cpp:376-379
	// maxThreshold=1000000us (1s), minThreshold=100000us (100ms) for 8-byte time
	const (
		maxThreshold = 1000 * time.Millisecond
		minThreshold = 100 * time.Millisecond
	)

	// see: CCRakNetUDT.cpp:381-384
	// If RTT unknown, return max threshold
	if c.lastRtt == 0 {
		return maxThreshold
	}

	// see: CCRakNetUDT.cpp:386
	// RTO = lastRttOnIncreaseSendRate * 2
	ret := c.lastRttOnIncreaseSendRate * 2

	// see: CCRakNetUDT.cpp:388-392
	if ret < minThreshold {
		return minThreshold
	}
	if ret > maxThreshold {
		return maxThreshold
	}
	return ret
}

// getSenderRTOForACK returns RTO used for ACK timing decisions.
// see: CCRakNetUDT::GetSenderRTOForACK in CCRakNetUDT.cpp:363-369
//
// Formula: RTO = RTT + RTTVarMultiple * RTTVar + SYN
// where RTTVar = maxRTT - minRTT and RTTVarMultiple = 4.0 (CCRakNetUDT.cpp:48)
func (c *UDT) getSenderRTOForACK() time.Duration {
	// see: CCRakNetUDT.cpp:365-366
	if c.lastRtt == 0 {
		return 0 // UNSET_TIME_US equivalent
	}

	// see: CCRakNetUDT.cpp:48 - RTTVarMultiple=4.0
	const rttVarMultiple = 4.0

	// see: CCRakNetUDT.cpp:367
	// RTTVar = maxRTT - minRTT
	rttVar := c.maxRtt - c.minRtt
	if rttVar < 0 {
		rttVar = 0
	}

	// see: CCRakNetUDT.cpp:368
	// RTO = RTT + 4*RTTVar + SYN
	rto := c.lastRtt + time.Duration(rttVarMultiple*float64(rttVar)) + time.Duration(c.synMicros)*time.Microsecond
	return rto
}

// OnSendBytes must be called for each datagram send to reduce the available budget
// in rate-based mode and increment sequence numbers.
// see: CCRakNetUDT::OnSendBytes in CCRakNetUDT.cpp:250-257
func (c *UDT) OnSendBytes(numBytes int) {
	// see: CCRakNetUDT.cpp:255-256
	if !c.isInSlowStart {
		c.bytesCanSendThisTick -= numBytes
		if c.bytesCanSendThisTick < 0 {
			c.bytesCanSendThisTick = 0
		}
	}
}

// OnDatagramSent should be called when a datagram is sent to increment sequence number.
// see: CCRakNetUDT::GetAndIncrementNextDatagramSequenceNumber in CCRakNetUDT.cpp:243-248
func (c *UDT) OnDatagramSent() uint32 {
	seq := c.nextDatagramSequenceNumber
	c.nextDatagramSequenceNumber++
	return seq
}

// updateRTT updates RTT tracking including min/max for variance calculation.
func (c *UDT) updateRTT(rtt time.Duration) {
	if rtt <= 0 {
		return
	}

	c.lastRtt = rtt

	// Update min/max RTT for variance calculation
	// see: CCRakNetUDT.h:233-234 - minRTT, maxRTT used in GetSenderRTOForACK
	if c.minRtt == 0 || rtt < c.minRtt {
		c.minRtt = rtt
	}
	if rtt > c.maxRtt {
		c.maxRtt = rtt
	}
}

// OnAck updates the controller on ACK arrival.
// see: CCRakNetUDT::OnAck in CCRakNetUDT.cpp:541-575
//
// Parameters:
//   - rtt: Round-trip time measurement
//   - isContinuousSend: Whether we've been continuously sending data
//   - totalAckedBytes: Cumulative total user-data bytes ACKed (for slow-start CWND)
//   - sequenceNumber: The sequence number being acknowledged
//
// Differences from native:
//   - Native receives hasBAndAS, B, AS parameters for receiver-reported arrival rate
//     (CCRakNetUDT.cpp:549-556). We don't have these, so we estimate AS locally.
//   - We update lastRttOnIncreaseSendRate during slow start (native does this at
//     CCRakNetUDT.cpp:566)
func (c *UDT) OnAck(rtt time.Duration, isContinuousSend bool, totalAckedBytes uint64, sequenceNumber uint32) {
	c.updateRTT(rtt)

	if c.isInSlowStart {
		// see: CCRakNetUDT.cpp:565-567
		// Update congestion control block and RTT during slow start
		c.nextCongestionControlBlock = c.nextDatagramSequenceNumber
		if rtt > 0 {
			c.lastRttOnIncreaseSendRate = rtt
		}

		// see: CCRakNetUDT.cpp:568 -> UpdateWindowSizeAndAckOnAckPreSlowStart
		// see: CCRakNetUDT.cpp:619-637
		// CWND = totalUserDataBytesAcked / MTU (in datagrams)
		if c.mtuBytes > 0 {
			cwnd := float64(totalAckedBytes) / float64(c.mtuBytes)

			// see: CCRakNetUDT.cpp:632-633 - clamp to minimum
			if cwnd < 2.0 {
				cwnd = 2.0
			}

			// see: CCRakNetUDT.cpp:625-631
			if cwnd >= c.cwndMaxThreshold {
				cwnd = c.cwndMaxThreshold
				// Difference from native: Native checks `if (AS!=UNDEFINED_TRANSFER_RATE)`
				// before calling EndSlowStart() (CCRakNetUDT.cpp:629-631). Since we don't
				// receive AS from the receiver, we use our local estimation method instead.
				c.endSlowStartWithEstimatedAS()
			}
			c.cwndDatagrams = cwnd
		}
		return
	}

	// see: CCRakNetUDT.cpp:570-572 -> UpdateWindowSizeAndAckOnAckPerSyn
	c.updateWindowSizeAndAckOnAckPerSyn(rtt, isContinuousSend, sequenceNumber)
}

// updateWindowSizeAndAckOnAckPerSyn handles post-slow-start rate adjustments.
// see: CCRakNetUDT::UpdateWindowSizeAndAckOnAckPerSyn in CCRakNetUDT.cpp:636-695
func (c *UDT) updateWindowSizeAndAckOnAckPerSyn(rtt time.Duration, isContinuousSend bool, sequenceNumber uint32) {
	// see: CCRakNetUDT.cpp:640-645
	if !isContinuousSend {
		c.nextCongestionControlBlock = c.nextDatagramSequenceNumber
		c.pingsLastInterval = c.pingsLastInterval[:0]
		return
	}

	// see: CCRakNetUDT.cpp:647-650
	// Collect RTT samples
	if rtt > 0 {
		c.pingsLastInterval = append(c.pingsLastInterval, float64(rtt.Microseconds()))
	}

	// see: CCRakNetUDT.cpp:648
	// static const int intervalSize=33; // Should be odd
	intervalSize := c.pingsLastIntervalTargetCount

	// see: CCRakNetUDT.cpp:649-650
	// Trim to keep only the most recent intervalSize samples
	if len(c.pingsLastInterval) > intervalSize {
		c.pingsLastInterval = c.pingsLastInterval[1:]
	}

	// see: CCRakNetUDT.cpp:651-654
	// Check all conditions before making rate decision:
	// 1. GreaterThan(sequenceNumber, nextCongestionControlBlock)
	// 2. sequenceNumber - nextCongestionControlBlock >= intervalSize
	// 3. pingsLastInterval.Size() == intervalSize
	if !greaterThan(sequenceNumber, c.nextCongestionControlBlock) {
		return
	}
	seqDiff := sequenceNumber - c.nextCongestionControlBlock
	if seqDiff < uint32(intervalSize) {
		return
	}
	if len(c.pingsLastInterval) != intervalSize {
		return
	}

	// see: CCRakNetUDT.cpp:655-663
	// Calculate slope sum and average
	samples := c.pingsLastInterval
	var slopeSum float64
	average := samples[0]
	for i := 1; i < len(samples); i++ {
		slopeSum += samples[i] - samples[i-1]
		average += samples[i]
	}
	average /= float64(len(samples))

	// see: CCRakNetUDT.cpp:665-687
	// Make rate decision based on slope
	if c.hadPacketlossThisBlock {
		// see: CCRakNetUDT.cpp:665-667
		// If we already slowed due to loss this block, don't take further action
	} else if slopeSum < -0.10*average {
		// see: CCRakNetUDT.cpp:668-672
		// Ping dropping => network is clearing, keep current rate (no action)
	} else if slopeSum > 0.10*average {
		// see: CCRakNetUDT.cpp:673-678
		// Ping rising => congestion building, slow down
		c.increaseTimeBetweenSends()
	} else {
		// see: CCRakNetUDT.cpp:679-687
		// Ping stable => network can handle more, speed up
		c.lastRttOnIncreaseSendRate = rtt
		c.decreaseTimeBetweenSends()
	}

	// see: CCRakNetUDT.cpp:689-691
	// Reset for next congestion control block
	c.pingsLastInterval = c.pingsLastInterval[:0]
	c.hadPacketlossThisBlock = false
	c.nextCongestionControlBlock = c.nextDatagramSequenceNumber

	// see: CCRakNetUDT.cpp:694
	// Note: Native also does lastRtt=rtt here, but we update in updateRTT() already
}

// OnNAK is called when a NACK is received.
// see: CCRakNetUDT::OnNAK in CCRakNetUDT.cpp:416-441
//
// Difference from native: Native checks `if (AS!=UNDEFINED_TRANSFER_RATE)` before
// calling EndSlowStart() (CCRakNetUDT.cpp:423-424). Since we don't receive AS from
// the receiver (no B/AS exchange), we call endSlowStartWithEstimatedAS() which
// estimates AS locally. Without this, we would be stuck in slow start forever
// when packet loss occurs.
func (c *UDT) OnNAK() {
	// see: CCRakNetUDT.cpp:421-425
	if c.isInSlowStart {
		c.endSlowStartWithEstimatedAS()
		return
	}

	// see: CCRakNetUDT.cpp:428-440
	if !c.hadPacketlossThisBlock {
		c.increaseTimeBetweenSends()
		c.hadPacketlossThisBlock = true
	}
}

// OnResend is called when a timeout-based retransmission is triggered.
// see: CCRakNetUDT::OnResend in CCRakNetUDT.cpp:395-413
//
// Same difference as OnNAK regarding AS check and endSlowStartWithEstimatedAS.
func (c *UDT) OnResend() {
	// see: CCRakNetUDT.cpp:399-403
	if c.isInSlowStart {
		c.endSlowStartWithEstimatedAS()
		return
	}

	// see: CCRakNetUDT.cpp:406-412
	if !c.hadPacketlossThisBlock {
		c.increaseTimeBetweenSends()
		c.hadPacketlossThisBlock = true
	}
}

// IsInSlowStart returns whether the controller is currently in slow start phase.
func (c *UDT) IsInSlowStart() bool {
	return c.isInSlowStart
}

// endSlowStartWithEstimatedAS exits slow start using a locally estimated AS.
// see: CCRakNetUDT::EndSlowStart in CCRakNetUDT.cpp:444-464
//
// Key Difference from Native:
// Native EndSlowStart() (CCRakNetUDT.cpp:444-464) expects AS to be set by the
// receiver via ACK extensions. It asserts `AS!=UNDEFINED_TRANSFER_RATE` and uses:
//
//	SND = 1.0 / AS  (CCRakNetUDT.cpp:453)
//
// Since our protocol doesn't exchange B/AS in ACKs, we must estimate AS locally.
// We derive AS from the CWND formula used in native code (CCRakNetUDT.h:204):
//
//	CWND = AS * (RTT + SYN) / MTU + 16
//
// Rearranging:
//
//	AS = (CWND - 16) * MTU / (RTT + SYN)
//
// Then: SND = 1.0 / AS
//
// This gives us a reasonable starting point for rate-based control based on
// what the network demonstrated it could handle during slow start.
func (c *UDT) endSlowStartWithEstimatedAS() {
	if !c.isInSlowStart {
		return
	}

	// Use the latest RTT; if unknown fallback to 50ms as a conservative default.
	rtt := c.lastRtt
	if rtt <= 0 {
		rtt = 50 * time.Millisecond
	}

	totalUs := float64(rtt.Microseconds()) + c.synMicros
	mtu := float64(c.mtuBytes)
	cwnd := c.cwndDatagrams

	// Estimate AS using derived formula from CWND = AS*(RTT+SYN)/MTU + 16
	asBytesPerUs := 0.0
	if totalUs > 0 && mtu > 0 {
		// The 16 offset comes from the CWND formula in CCRakNetUDT.h:204
		asBytesPerUs = (maxFloat(cwnd-16.0, 0.0) * mtu) / totalUs
	}

	// see: CCRakNetUDT.cpp:92-94
	// Fallback to DEFAULT_TRANSFER_RATE (0.0036) if estimation failed
	if asBytesPerUs <= 0 {
		asBytesPerUs = 0.0036
	}

	// see: CCRakNetUDT.cpp:453
	// SND = 1.0 / AS
	c.sndMicrosPerByte = 1.0 / asBytesPerUs

	// see: CCRakNetUDT.cpp:454 -> CapMinSnd
	// Ensure SND is within reasonable bounds
	if c.sndMicrosPerByte <= 0 {
		c.sndMicrosPerByte = 1.0 / 0.0036
	}
	c.capMinSnd()

	// see: CCRakNetUDT.cpp:452
	c.isInSlowStart = false

	// Reset the tick budget so next tick will refill according to SND
	c.bytesCanSendThisTick = 0
}

// increaseTimeBetweenSends slows down the send rate.
// see: CCRakNetUDT::IncreaseTimeBetweenSends in CCRakNetUDT.cpp:761-778
//
// Uses a non-linear adjustment where higher SND values increase slower.
// This helps convergence: fast senders slow down quickly, slow senders slow down gently.
//
// Formula (CCRakNetUDT.cpp:770-774):
//
//	increment = 0.02 * ((SND+1)^2) / (501^2)
//	SND *= (1.02 - increment)
//
// At SND=500: increment ≈ 0.02, so multiplier ≈ 1.0 (minimal slowdown)
// At SND=0:   increment ≈ 0,    so multiplier ≈ 1.02 (2% slowdown)
func (c *UDT) increaseTimeBetweenSends() {
	// see: CCRakNetUDT.cpp:770-774
	inc := 0.02 * ((c.sndMicrosPerByte + 1.0) * (c.sndMicrosPerByte + 1.0)) / (501.0 * 501.0)
	c.sndMicrosPerByte *= (1.02 - inc)

	// see: CCRakNetUDT.cpp:778 -> CapMinSnd
	c.capMinSnd()
}

// decreaseTimeBetweenSends speeds up the send rate.
// see: CCRakNetUDT::DecreaseTimeBetweenSends in CCRakNetUDT.cpp:780-787
//
// Uses similar non-linear adjustment as increaseTimeBetweenSends.
//
// Formula (CCRakNetUDT.cpp:782-786):
//
//	increment = 0.01 * ((SND+1)^2) / (501^2)
//	SND *= (0.99 - increment)
//
// Note: Native code does NOT have a lower bound check here. We add one to prevent
// SND from becoming zero or negative, which would cause division issues elsewhere.
func (c *UDT) decreaseTimeBetweenSends() {
	// see: CCRakNetUDT.cpp:782-786
	inc := 0.01 * ((c.sndMicrosPerByte + 1.0) * (c.sndMicrosPerByte + 1.0)) / (501.0 * 501.0)
	c.sndMicrosPerByte *= (0.99 - inc)

	// Safety floor not present in native code, added to prevent pathological values
	if c.sndMicrosPerByte < 0.000001 {
		c.sndMicrosPerByte = 0.000001
	}
}

// capMinSnd caps SND to prevent pathologically slow send rates.
// see: CCRakNetUDT::CapMinSnd in CCRakNetUDT.cpp:750-759
//
// SND > 500 means sending slower than a 28.8kbps modem, which indicates a bug.
// (CCRakNetUDT.cpp:758-759)
func (c *UDT) capMinSnd() {
	// see: CCRakNetUDT.cpp:755-759
	if c.sndMicrosPerByte > 500.0 {
		c.sndMicrosPerByte = 500.0
	}
}

// greaterThan compares sequence numbers accounting for wraparound.
// see: CCRakNetUDT::GreaterThan in CCRakNetUDT.cpp:349-354
//
// Uses half-span comparison: a > b if (b - a) > halfSpan
// This correctly handles wraparound for sequence numbers.
func greaterThan(a, b uint32) bool {
	// see: CCRakNetUDT.cpp:352-353
	const halfSpan = uint32(0xFFFFFF) / 2
	return b != a && (b-a) > halfSpan
}

// maxFloat returns the maximum of two float64 values.
func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
