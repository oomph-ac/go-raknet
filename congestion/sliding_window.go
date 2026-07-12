package congestion

import (
	"math"
	"time"
)

// unsetTime is the sentinel value indicating an uninitialized time measurement.
// see: CCRakNetSlidingWindow.cpp:15 - static const double UNSET_TIME_US=-1;
const unsetTime float64 = -1

// SlidingWindow is a Go adaptation of RakNet's CCRakNetSlidingWindow congestion control.
// This is a simpler algorithm than UDT, implementing standard TCP-like slow start
// and congestion avoidance.
//
// Reference: CCRakNetSlidingWindow.cpp, CCRakNetSlidingWindow.h
// Source: https://github.com/facebookarchive/RakNet
// Enabled in native code with: USE_SLIDING_WINDOW_CONGESTION_CONTROL=1
//
// Algorithm Overview:
//   - Slow Start: CWND increases by 1 MTU per ACK (exponential growth)
//   - Congestion Avoidance: CWND increases by MTU^2/CWND per ACK (linear growth)
//   - On packet loss (NACK): ssThresh = CWND/2, stay in congestion avoidance
//   - On resend (timeout): ssThresh = CWND/2, CWND = MTU (back to slow start)
//
// Key differences from UDT:
//   - No rate-based control (SND), purely window-based
//   - Simpler RTT estimation using exponential moving average
//   - No packet pair measurements or arrival rate calculations
type SlidingWindow struct {
	// mtu is the maximum transmission unit including UDP header.
	// see: CCRakNetSlidingWindow.h:90 - MAXIMUM_MTU_INCLUDING_UDP_HEADER
	mtu uint32

	// cwnd is the congestion window size in bytes.
	// see: CCRakNetSlidingWindow.cpp:50 - cwnd=maxDatagramPayload (initialized to 1 MTU)
	// see: CCRakNetSlidingWindow.h:70 - double cwnd
	cwnd float64

	// ssThresh is the slow start threshold in bytes.
	// When cwnd <= ssThresh or ssThresh == 0, we're in slow start.
	// see: CCRakNetSlidingWindow.cpp:51 - ssThresh=0.0
	// see: CCRakNetSlidingWindow.h:71 - double ssThresh
	ssThresh float64

	// lastRtt is the most recent RTT measurement in microseconds.
	// see: CCRakNetSlidingWindow.cpp:47 - lastRtt=UNSET_TIME_US
	// see: CCRakNetSlidingWindow.h:84 - double lastRtt
	lastRtt float64

	// estimatedRTT is the smoothed RTT estimate in microseconds.
	// see: CCRakNetSlidingWindow.cpp:47 - estimatedRTT=UNSET_TIME_US
	// see: CCRakNetSlidingWindow.h:85 - double estimatedRTT
	estimatedRTT float64

	// deviationRtt is the RTT deviation (similar to TCP's RTTVar).
	// see: CCRakNetSlidingWindow.cpp:47 - deviationRtt=UNSET_TIME_US
	// see: CCRakNetSlidingWindow.h:86 - double deviationRtt
	deviationRtt float64

	// oldestUnsentAck is the timestamp of the oldest ACK waiting to be sent.
	// see: CCRakNetSlidingWindow.cpp:52 - oldestUnsentAck=0
	// see: CCRakNetSlidingWindow.h:76 - CCTimeType oldestUnsentAck
	oldestUnsentAck int64

	// nextDatagramSequenceNumber is the next sequence number to assign.
	// see: CCRakNetSlidingWindow.cpp:53 - nextDatagramSequenceNumber=0
	// see: CCRakNetSlidingWindow.h:77 - DatagramSequenceNumberType nextDatagramSequenceNumber
	nextDatagramSequenceNumber uint32

	// nextCongestionControlBlock marks the start of the next congestion epoch.
	// see: CCRakNetSlidingWindow.cpp:54 - nextCongestionControlBlock=0
	// see: CCRakNetSlidingWindow.h:78 - DatagramSequenceNumberType nextCongestionControlBlock
	nextCongestionControlBlock uint32

	// backoffThisBlock prevents multiple backoffs per congestion epoch.
	// see: CCRakNetSlidingWindow.cpp:55 - backoffThisBlock=false
	// see: CCRakNetSlidingWindow.h:79 - bool backoffThisBlock
	backoffThisBlock bool

	// speedUpThisBlock prevents multiple speed-ups per congestion epoch.
	// see: CCRakNetSlidingWindow.cpp:55 - speedUpThisBlock=false
	// see: CCRakNetSlidingWindow.h:80 - bool speedUpThisBlock
	speedUpThisBlock bool

	// expectedNextSequenceNumber is the next sequence number we expect to receive.
	// see: CCRakNetSlidingWindow.cpp:56 - expectedNextSequenceNumber=0
	// see: CCRakNetSlidingWindow.h:81 - DatagramSequenceNumberType expectedNextSequenceNumber
	expectedNextSequenceNumber uint32

	// isContinuousSend tracks whether we're continuously sending data.
	// see: CCRakNetSlidingWindow.cpp:57 - _isContinuousSend=false
	// see: CCRakNetSlidingWindow.h:91 - bool _isContinuousSend
	isContinuousSend bool

	// synMicros is the SYN interval in microseconds (10ms).
	// see: CCRakNetSlidingWindow.cpp:19-21 - static const CCTimeType SYN=10000
	synMicros float64
}

// NewSlidingWindow creates a new sliding window congestion controller.
// see: CCRakNetSlidingWindow::Init in CCRakNetSlidingWindow.cpp:43-58
func NewSlidingWindow(mtuBytes int) *SlidingWindow {
	// see: CCRakNetSlidingWindow.cpp:19-21
	// SYN=10000 for CC_TIME_TYPE_BYTES==8 (microseconds)
	const synUs = 10000.0

	return &SlidingWindow{
		// see: CCRakNetSlidingWindow.cpp:48-49
		mtu: uint32(mtuBytes),

		// see: CCRakNetSlidingWindow.cpp:50 - cwnd=maxDatagramPayload
		// Initial CWND is 1 MTU
		cwnd: float64(mtuBytes),

		// see: CCRakNetSlidingWindow.cpp:51 - ssThresh=0.0
		// ssThresh=0 means we're in slow start (no threshold set yet)
		ssThresh: 0.0,

		// see: CCRakNetSlidingWindow.cpp:47
		lastRtt:      unsetTime,
		estimatedRTT: unsetTime,
		deviationRtt: unsetTime,

		// see: CCRakNetSlidingWindow.cpp:52-56
		oldestUnsentAck:            0,
		nextDatagramSequenceNumber: 0,
		nextCongestionControlBlock: 0,
		backoffThisBlock:           false,
		speedUpThisBlock:           false,
		expectedNextSequenceNumber: 0,

		// see: CCRakNetSlidingWindow.cpp:57
		isContinuousSend: false,

		synMicros: synUs,
	}
}

// GetTransmissionBandwidth returns how many bytes can be sent for new data.
// see: CCRakNetSlidingWindow::GetTransmissionBandwidth in CCRakNetSlidingWindow.cpp:75-86
//
// Returns cwnd - unacknowledgedBytes if positive, else 0.
// This is simpler than UDT as it's purely window-based with no rate control.
func (c *SlidingWindow) GetTransmissionBandwidth(timeSinceLastTick time.Duration, unackedBytes int, isContinuousSend bool) int {
	// see: CCRakNetSlidingWindow.cpp:77-78 - unused parameters
	_ = timeSinceLastTick

	// see: CCRakNetSlidingWindow.cpp:80
	c.isContinuousSend = isContinuousSend

	// see: CCRakNetSlidingWindow.cpp:82-85
	if unackedBytes <= int(c.cwnd) {
		return int(c.cwnd) - unackedBytes
	}
	return 0
}

// GetRetransmissionBandwidth returns how many bytes can be sent for retransmissions.
// see: CCRakNetSlidingWindow::GetRetransmissionBandwidth in CCRakNetSlidingWindow.cpp:66-73
//
// For sliding window, this simply returns unacknowledgedBytes (all can be retransmitted).
func (c *SlidingWindow) GetRetransmissionBandwidth(timeSinceLastTick time.Duration, unackedBytes int, isContinuousSend bool) int {
	// see: CCRakNetSlidingWindow.cpp:68-71 - unused parameters
	_ = timeSinceLastTick
	_ = isContinuousSend

	// see: CCRakNetSlidingWindow.cpp:72
	return unackedBytes
}

// ShouldSendACKs determines whether ACKs should be sent now.
// see: CCRakNetSlidingWindow::ShouldSendACKs in CCRakNetSlidingWindow.cpp:88-101
//
// Returns true if:
//   - RTO is unknown (send immediately to establish timing)
//   - Time since oldest unsent ACK >= SYN interval (10ms)
func (c *SlidingWindow) ShouldSendACKs(curTime int64, estimatedTimeToNextTick int64) bool {
	// see: CCRakNetSlidingWindow.cpp:90
	rto := c.getSenderRTOForACK()

	// see: CCRakNetSlidingWindow.cpp:91 - unused parameter
	_ = estimatedTimeToNextTick

	// see: CCRakNetSlidingWindow.cpp:93-98
	// If RTO is unset (rto == UNSET_TIME_US), send ACKs immediately
	if rto == time.Duration(unsetTime) {
		return true
	}

	// see: CCRakNetSlidingWindow.cpp:100
	// Return true if curTime >= oldestUnsentAck + SYN
	synMs := int64(c.synMicros / 1000) // Convert microseconds to milliseconds
	return curTime >= c.oldestUnsentAck+synMs
}

// OnQueueACK records when an ACK is queued for sending.
// see: CCRakNetSlidingWindow::OnGotPacket in CCRakNetSlidingWindow.cpp:134-135
func (c *SlidingWindow) OnQueueACK(curTime int64) {
	// see: CCRakNetSlidingWindow.cpp:134-135
	if c.oldestUnsentAck == 0 {
		c.oldestUnsentAck = curTime
	}
}

// OnSendACK resets the oldest unsent ACK timestamp.
// see: CCRakNetSlidingWindow::OnSendAck in CCRakNetSlidingWindow.cpp:273-279
func (c *SlidingWindow) OnSendACK() {
	// see: CCRakNetSlidingWindow.cpp:278
	c.oldestUnsentAck = 0
}

// GetRTOForRetransmission returns the retransmission timeout.
// see: CCRakNetSlidingWindow::GetRTOForRetransmission in CCRakNetSlidingWindow.cpp:288-314
//
// Formula: RTO = u * estimatedRTT + q * deviationRtt + additionalVariance
// where u=2.0, q=4.0, additionalVariance=30ms
// Clamped to maxThreshold of 2000ms.
func (c *SlidingWindow) GetRTOForRetransmission() time.Duration {
	// see: CCRakNetSlidingWindow.cpp:290 - unused parameter timesSent
	// see: CCRakNetSlidingWindow.cpp:292-300
	// For CC_TIME_TYPE_BYTES==8 (microseconds):
	const (
		maxThresholdUs     = 2000000 // 2000ms
		additionalVariance = 30000   // 30ms
	)

	// see: CCRakNetSlidingWindow.cpp:303-304
	if c.estimatedRTT == unsetTime {
		return time.Duration(maxThresholdUs) * time.Microsecond
	}

	// see: CCRakNetSlidingWindow.cpp:306-308
	// u=2.0, q=4.0
	u := 2.0
	q := 4.0

	// see: CCRakNetSlidingWindow.cpp:310
	threshold := u*c.estimatedRTT + q*c.deviationRtt + additionalVariance

	// see: CCRakNetSlidingWindow.cpp:311-313
	if threshold > maxThresholdUs {
		return time.Duration(maxThresholdUs) * time.Microsecond
	}
	return time.Duration(threshold) * time.Microsecond
}

// getSenderRTOForACK returns the RTO used for ACK timing decisions.
// see: CCRakNetSlidingWindow::GetSenderRTOForACK in CCRakNetSlidingWindow.cpp:360-365
//
// Returns lastRtt + SYN, or UNSET_TIME if RTT is unknown.
func (c *SlidingWindow) getSenderRTOForACK() time.Duration {
	// see: CCRakNetSlidingWindow.cpp:362-363
	if c.lastRtt == unsetTime {
		return time.Duration(unsetTime)
	}

	// see: CCRakNetSlidingWindow.cpp:364
	return time.Duration(c.lastRtt+c.synMicros) * time.Microsecond
}

// OnSendBytes is called when bytes are sent.
// see: CCRakNetSlidingWindow::OnSendBytes in CCRakNetSlidingWindow.cpp:115-119
//
// This is a no-op for sliding window as it doesn't use rate-based control.
func (c *SlidingWindow) OnSendBytes(numBytes int) {
	// see: CCRakNetSlidingWindow.cpp:117-118 - parameters are unused
	_ = numBytes
}

// OnDatagramSent returns the next sequence number and increments it.
// see: CCRakNetSlidingWindow::GetAndIncrementNextDatagramSequenceNumber in CCRakNetSlidingWindow.cpp:108-113
func (c *SlidingWindow) OnDatagramSent() uint32 {
	// see: CCRakNetSlidingWindow.cpp:110-112
	seq := c.nextDatagramSequenceNumber
	c.nextDatagramSequenceNumber++
	return seq
}

// OnAck is called when an ACK is received.
// see: CCRakNetSlidingWindow::OnAck in CCRakNetSlidingWindow.cpp:201-256
//
// Updates RTT estimates and adjusts CWND based on slow start or congestion avoidance.
func (c *SlidingWindow) OnAck(rtt time.Duration, isContinuousSend bool, totalAckedBytes uint64, sequenceNumber uint32) {
	// see: CCRakNetSlidingWindow.cpp:203-208 - unused parameters in native
	_ = totalAckedBytes

	// Convert RTT to microseconds for internal calculations
	rttUs := float64(rtt.Microseconds())

	// see: CCRakNetSlidingWindow.cpp:210
	c.lastRtt = rttUs

	// see: CCRakNetSlidingWindow.cpp:211-222
	// Update smoothed RTT using exponential moving average
	if c.estimatedRTT == unsetTime {
		// First RTT sample
		c.estimatedRTT = rttUs
		c.deviationRtt = rttUs
	} else {
		// see: CCRakNetSlidingWindow.cpp:218-221
		// d = 0.05 (smoothing factor)
		d := 0.05
		difference := rttUs - c.estimatedRTT
		c.estimatedRTT = c.estimatedRTT + d*difference
		c.deviationRtt = c.deviationRtt + d*(math.Abs(difference)-c.deviationRtt)
	}

	// see: CCRakNetSlidingWindow.cpp:224
	c.isContinuousSend = isContinuousSend

	// see: CCRakNetSlidingWindow.cpp:226-227
	if !isContinuousSend {
		return
	}

	// see: CCRakNetSlidingWindow.cpp:229-237
	// Check if we're entering a new congestion control period
	isNewCongestionControlPeriod := slidingWindowGreaterThan(sequenceNumber, c.nextCongestionControlBlock)

	if isNewCongestionControlPeriod {
		// see: CCRakNetSlidingWindow.cpp:234-236
		c.backoffThisBlock = false
		c.speedUpThisBlock = false
		c.nextCongestionControlBlock = c.nextDatagramSequenceNumber
	}

	// see: CCRakNetSlidingWindow.cpp:239-255
	if c.isInSlowStart() {
		// see: CCRakNetSlidingWindow.cpp:241
		// Slow start: increase CWND by 1 MTU per ACK (exponential growth)
		c.cwnd += float64(c.mtu)

		// see: CCRakNetSlidingWindow.cpp:242-243
		// If CWND exceeds ssThresh, transition to congestion avoidance
		if c.cwnd > c.ssThresh && c.ssThresh != 0 {
			c.cwnd = c.ssThresh + float64(c.mtu)*float64(c.mtu)/c.cwnd
		}
	} else if isNewCongestionControlPeriod {
		// see: CCRakNetSlidingWindow.cpp:249-251
		// Congestion avoidance: increase CWND by MTU^2/CWND per RTT (linear growth)
		c.cwnd += float64(c.mtu) * float64(c.mtu) / c.cwnd
	}
}

// OnNAK is called when a NACK is received.
// see: CCRakNetSlidingWindow::OnNAK in CCRakNetSlidingWindow.cpp:186-199
//
// Sets ssThresh to CWND/2 to start congestion avoidance.
func (c *SlidingWindow) OnNAK() {
	// see: CCRakNetSlidingWindow.cpp:191-198
	if c.isContinuousSend && !c.backoffThisBlock {
		// see: CCRakNetSlidingWindow.cpp:193-194
		// Start congestion avoidance: set ssThresh to half of current CWND
		c.ssThresh = c.cwnd / 2
	}
}

// OnResend is called when a timeout-based retransmission is triggered.
// see: CCRakNetSlidingWindow::OnResend in CCRakNetSlidingWindow.cpp:163-184
//
// Performs multiplicative decrease: ssThresh = CWND/2, CWND = MTU.
// This puts us back into slow start.
func (c *SlidingWindow) OnResend() {
	// see: CCRakNetSlidingWindow.cpp:165-166 - unused parameters

	// see: CCRakNetSlidingWindow.cpp:168-183
	if c.isContinuousSend && !c.backoffThisBlock && c.cwnd > float64(c.mtu)*2 {
		// see: CCRakNetSlidingWindow.cpp:170-172
		// Spec says 1/2 cwnd, but native comment notes it never recovers
		// because cwnd increases too slowly, so they still use ssThresh=cwnd/2
		c.ssThresh = c.cwnd / 2

		// see: CCRakNetSlidingWindow.cpp:173-174
		if c.ssThresh < float64(c.mtu) {
			c.ssThresh = float64(c.mtu)
		}

		// see: CCRakNetSlidingWindow.cpp:175
		// Reset CWND to 1 MTU (back to slow start)
		c.cwnd = float64(c.mtu)

		// see: CCRakNetSlidingWindow.cpp:177-179
		// Only backoff once per period
		c.nextCongestionControlBlock = c.nextDatagramSequenceNumber
		c.backoffThisBlock = true
	}
}

// IsInSlowStart returns whether the controller is in slow start phase.
// see: CCRakNetSlidingWindow::IsInSlowStart in CCRakNetSlidingWindow.cpp:367-370
func (c *SlidingWindow) IsInSlowStart() bool {
	return c.isInSlowStart()
}

// isInSlowStart is the internal slow start check.
// see: CCRakNetSlidingWindow::IsInSlowStart in CCRakNetSlidingWindow.cpp:367-370
func (c *SlidingWindow) isInSlowStart() bool {
	// see: CCRakNetSlidingWindow.cpp:369
	// In slow start if cwnd <= ssThresh OR ssThresh == 0 (threshold not yet set)
	return c.cwnd <= c.ssThresh || c.ssThresh == 0
}

// slidingWindowGreaterThan compares sequence numbers accounting for wraparound.
// see: CCRakNetSlidingWindow::GreaterThan in CCRakNetSlidingWindow.cpp:341-346
func slidingWindowGreaterThan(a, b uint32) bool {
	// see: CCRakNetSlidingWindow.cpp:344-345
	const halfSpan = uint32(0xFFFFFF) / 2
	return b != a && (b-a) > halfSpan
}
