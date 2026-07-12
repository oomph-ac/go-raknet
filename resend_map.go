package raknet

import (
	"time"
)

// resendMap is a map of packets, used to recover datagrams if the other end of
// the connection ended up not having them. It also maintains RTT/RTO
// statistics for more accurate timeout handling.
type resendMap struct {
	unacknowledged map[uint24]resendRecord

	// smoothed RTT and RTT variance as per RFC 6298.
	srtt   time.Duration
	rttVar time.Duration
	rto    time.Duration

	// inFlightBytes tracks the total number of bytes currently in flight for
	// congestion control purposes.
	inFlightBytes int
	// lastSample stores the most recent RTT sample before smoothing.
	lastSample time.Duration
}

// resendRecord represents one or more packets with a timestamp from when they
// were initially sent. It may be either acknowledged or NACKed by the other end.
type resendRecord struct {
	packets   []*packet
	timestamp time.Time
	length    int
}

// newRecoveryQueue returns a new initialised recovery queue.
func newRecoveryQueue() *resendMap {
	return &resendMap{
		unacknowledged: make(map[uint24]resendRecord),
	}
}

// add puts the packets at the index passed and records the current time and
// encoded datagram length in bytes.
func (m *resendMap) add(index uint24, packets []*packet, length int) {
	m.unacknowledged[index] = resendRecord{packets: packets, timestamp: time.Now(), length: length}
	m.inFlightBytes += length
}

// acknowledge marks packets with the index passed as acknowledged. The packets
// are removed from the resendMap and returned if found.
func (m *resendMap) acknowledge(index uint24) ([]*packet, bool) {
	return m.remove(index, 1)
}

// retransmit looks up packets with an index from the resendMap so that they may
// be resent.
func (m *resendMap) retransmit(index uint24) ([]*packet, bool) {
	return m.remove(index, 2)
}

// remove deletes an index from the resendMap and, for original transmissions
// (mul == 1), feeds the RTT sample into the SRTT/RTTVAR estimator.
func (m *resendMap) remove(index uint24, mul int) ([]*packet, bool) {
	record, ok := m.unacknowledged[index]
	if !ok {
		return nil, false
	}
	delete(m.unacknowledged, index)

	// Maintain the aggregate in-flight byte counter.
	m.inFlightBytes -= record.length

	// For retransmissions (mul > 1), we intentionally do not update RTT in
	// order to follow Karn's algorithm and avoid ambiguous samples.
	if mul == 1 {
		sample := time.Since(record.timestamp)
		m.lastSample = sample
		m.updateRTT(sample)
	}
	return record.packets, true
}

// updateRTT updates SRTT, RTTVAR and RTO based on a new RTT sample.
func (m *resendMap) updateRTT(sample time.Duration) {
	if sample <= 0 {
		return
	}

	const (
		minRTO = 50 * time.Millisecond
		maxRTO = 10 * time.Second
	)

	// First measurement initialisation, RFC 6298 section 2.2.
	if m.srtt == 0 {
		m.srtt = sample
		m.rttVar = sample / 2
	} else {
		absDiff := m.srtt - sample
		if absDiff < 0 {
			absDiff = -absDiff
		}
		//m.rttVar = time.Duration((1-beta)*float64(m.rttVar) + beta*float64(absDiff))
		//m.srtt = time.Duration((1-alpha)*float64(m.srtt) + alpha*float64(sample))
		m.srtt = (7*m.srtt + 1*sample) / 8
		m.rttVar = (3*m.rttVar + 1*absDiff) / 4
	}

	// RTO = SRTT + 4*RTTVAR with bounds.
	rto := m.srtt + 4*m.rttVar
	if rto < minRTO {
		rto = minRTO
	} else if rto > maxRTO {
		rto = maxRTO
	}
	m.rto = rto
}

// rtt returns the current smoothed RTT estimate. If no samples have been
// recorded yet, a reasonable default is returned.
func (m *resendMap) rtt() time.Duration {
	return m.rttValue(true)
}

// rttVariance returns the current RTT variance estimate. If no samples have been
// recorded yet, a reasonable default is returned.
func (m *resendMap) rttVariance() time.Duration {
	return m.rttVar
}

// rttValue returns either the smoothed RTT (SRTT) or the most recent RTT
// sample depending on the smoothed flag.
func (m *resendMap) rttValue(smoothed bool) time.Duration {
	const defaultRTT = 50 * time.Millisecond
	if smoothed {
		if m.srtt != 0 {
			return m.srtt
		}
		return defaultRTT
	}
	if m.lastSample != 0 {
		return m.lastSample
	}
	return defaultRTT
}

// timeout returns the current retransmission timeout (RTO) estimate.
func (m *resendMap) timeout() time.Duration {
	if m.rto != 0 {
		return m.rto
	}
	// Conservative default RTO before any measurement.
	return 200 * time.Millisecond
}

// inFlightBytesEstimate returns the total number of bytes currently
// unacknowledged and thus considered in flight.
func (m *resendMap) inFlightBytesEstimate() int {
	return m.inFlightBytes
}
