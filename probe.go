// Package probe offers utilities for actively probing servers. The idea is to probe our own servers
// as a censor would, looking for giveaways that the server is used for circumvention.
package probe

import (
	"crypto/rand"
	"fmt"
	"net"
	"time"

	"github.com/montanaflynn/stats"

	"github.com/getlantern/errors"
	"github.com/getlantern/probednet"
	"github.com/getlantern/probednet/pktutil"
)

// Config for a probe.
type Config struct {
	// Network to use (ala net.Dial).
	Network string

	// Address to probe.
	Address string

	// TODO: support timeout
}

// FailedCheck is a special error type indicating that a probed server failed a check. This can be
// used to distinguish detectability errors from errors rooted in things like network failures.
type FailedCheck interface {
	error
	isFailedCheck()
}

type failedCheck struct{ error }

func (fc failedCheck) isFailedCheck() {}

// ForRandomizedTransport probes for evidence of a randomized transport like obsf4 or Lampshade.
func ForRandomizedTransport(cfg Config) error {

	// 1. Establish a baseline response using single-byte payloads.
	// 2. Using a binary search (up to a maximum payload size), find the payload length at which the
	//    response differs from the baseline.
	// 3. If the response never changes up to the maximum payload size, the check passes.

	const (
		maxPayloadSize = 1024 * 1024
		// baselinePackets = 100

		// debugging
		baselinePackets = 10
	)

	fmt.Println("establishing baseline")

	baselineResp, err := establishBaselineResponse(cfg, baselinePackets)
	if err != nil {
		return errors.New("failed to establish baseline response: %v", err)
	}

	fmt.Printf(
		"baseline response:\n\tmin response time: %v\n\tmax response time: %v\n\tresponse time standard deviation: %v\n",
		time.Duration(baselineResp.minResponseTime),
		time.Duration(baselineResp.maxResponseTime),
		time.Duration(baselineResp.responseTimeStdDev),
	)

	respWithinBoundsFull := func(payloadSize int) (_ bool, explanation string, _ error) {
		fmt.Printf("trying %d byte payload\n", payloadSize)

		payload := make([]byte, payloadSize)
		_, err := rand.Read(payload)
		if err != nil {
			return false, "", errors.New("failed to generate payload: %v", err)
		}

		resp, err := sendTCPPayload(cfg.Network, cfg.Address, payload)
		if err != nil {
			return false, "", errors.New("failed to send payload: %v", err)
		}

		return baselineResp.withinAcceptedBounds(*resp)
	}
	respOutOfBounds := func(payloadSize int) (bool, error) {
		ok, explanation, err := respWithinBoundsFull(payloadSize)
		if err == nil && !ok {
			fmt.Println("explanation:", explanation)
		}
		// TODO: this is clunky
		return !ok, err
	}

	fmt.Println("trying varying payload sizes")

	payloadSizeThreshold, err := minBinarySearch(2, maxPayloadSize, respOutOfBounds)
	if err != nil {
		return errors.New("search for payload size threshold failed: %v", err)
	}
	if payloadSizeThreshold > 0 {
		errMsg := fmt.Sprintf(
			"response to payload of %d bytes fell outside bounds established by baseline",
			payloadSizeThreshold,
		)
		_, explanation, _ := respWithinBoundsFull(payloadSizeThreshold)
		if explanation != "" {
			errMsg = fmt.Sprintf("%s: %s", errMsg, explanation)
		}
		fmt.Println("found evidence of randomized transport:", errMsg)
		return failedCheck{errors.New(errMsg)}
	}
	return nil
}

type tcpResponse struct {
	sent    []pktutil.TransportPacket
	packets []pktutil.TransportPacket
}

// We define the respone time as the time between the last packet we sent and the first packet we
// received with any flag other than ACK.
func (r tcpResponse) responseTime() (time.Duration, error) {
	if len(r.sent) < 1 {
		return 0, errors.New("no sent packets")
	}
	if len(r.packets) < 1 {
		return 0, errors.New("no response packets")
	}

	firstSent := r.sent[0]
	var firstResponse *pktutil.TransportPacket
	for _, pkt := range r.packets {
		if pkt.HasAnyFlags(
			pktutil.SYN, pktutil.FIN, pktutil.URG, pktutil.PSH,
			pktutil.RST, pktutil.ECE, pktutil.CWR, pktutil.NS,
		) {
			firstResponse = &pkt
			break
		}
	}
	if firstResponse == nil {
		return 0, errors.New("could not find a response packet")
	}

	if firstSent.Timestamp.IsZero() || firstResponse.Timestamp.IsZero() {
		return 0, errors.New("no timestamps on captured packets")
	}
	fmt.Printf("firstNonACK.timestamp: %v, firstSent.timestamp: %v\n", firstResponse.Timestamp, firstSent.Timestamp)
	return firstResponse.Timestamp.Sub(firstSent.Timestamp), nil
}

// Establishes a connection and sends the input payload. Returns all packets sent in response. The
// response is guaranteed to have at least one packet.
func sendTCPPayload(network, address string, payload []byte) (*tcpResponse, error) {
	// TODO: currently assuming in-order packet capture - vet or fix this

	conn, err := probednet.Dial(network, address)
	if err != nil {
		return nil, errors.New("failed to dial address: %v", err)
	}

	capturedPackets := []probednet.Packet{}
	captureComplete := make(chan struct{})
	captureErrors := make(chan error)
	go func() {
		for pkt := range conn.CapturedPackets() {
			capturedPackets = append(capturedPackets, pkt)
		}
		close(captureComplete)
	}()
	go func() {
		for err := range conn.CaptureErrors() {
			captureErrors <- err
		}
	}()

	if _, err := conn.Write(payload); err != nil {
		conn.Close()
		return nil, errors.New("failed to write payload: %v", err)
	}

	// Wait for a response.
	for {
		_, err := conn.Read(make([]byte, 1024))
		if err == nil {
			break
		}
		if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
			continue
		}
		// We don't care about non-temporary errors.
		// TODO: we do want to know about network issues - how can we distinguish these?
		break
	}

	conn.Close()
	<-captureComplete

	select {
	case err := <-captureErrors:
		return nil, errors.New("packet capture error: %v", err)
	default:
	}

	fmt.Println("================== captured packets ===================")

	pkts := make([]pktutil.TransportPacket, len(capturedPackets))
	for i, pkt := range capturedPackets {
		decoded, err := pktutil.DecodeTransportPacket(pkt.Data)
		if err != nil {
			return nil, errors.New("failed to decode packet: %v", err)
		}
		decoded.Timestamp = pkt.Timestamp
		pkts[i] = *decoded

		fmt.Println(decoded.Pprint())
	}

	var (
		payloadPkts  []pktutil.TransportPacket
		responsePkts []pktutil.TransportPacket
	)
	for _, pkt := range pkts {
		if pkt.DestinedFor(conn.RemoteAddr()) && len(pkt.Payload) > 0 {
			payloadPkts = append(payloadPkts, pkt)
		}
		// We count packets as response packets iff they come after the first payload packet and are
		// more than a simple ACK.
		if len(payloadPkts) > 0 && pkt.DestinedFor(conn.LocalAddr()) && pkt.HasAnyFlags(
			pktutil.SYN, pktutil.FIN, pktutil.URG, pktutil.PSH,
			pktutil.RST, pktutil.ECE, pktutil.CWR, pktutil.NS,
		) {
			responsePkts = append(responsePkts, pkt)
		}
	}
	if len(payloadPkts) == 0 {
		return nil, errors.New("unable to find payload packets in capture output")
	}
	if len(responsePkts) == 0 {
		return nil, errors.New("unable to find response packets in capture output")
	}

	// fmt.Println("=================================")
	// fmt.Println("============= sent ==============")
	// fmt.Println("=================================")
	// fmt.Println(payloadPkt.Pprint())

	// fmt.Println("=================================")
	// fmt.Println("=========== response ============")
	// fmt.Println("=================================")
	// for _, p := range responsePkts {
	// 	fmt.Println(p.Pprint())
	// }

	return &tcpResponse{payloadPkts, responsePkts}, nil
}

type responseBaseline struct {
	minResponseTime    float64
	maxResponseTime    float64
	responseTimeStdDev float64
}

// Establishes a baseline response to single-packet payloads. A new connection is established for
// each payload.
func establishBaselineResponse(cfg Config, baselinePackets int) (*responseBaseline, error) {
	var testPayload = []byte{1}

	responseTimes := make([]int64, baselinePackets)
	// TODO: track responses: payloads, flags, how many packets
	for i := 0; i < baselinePackets; i++ {
		resp, err := sendTCPPayload(cfg.Network, cfg.Address, testPayload)
		if err != nil {
			return nil, errors.New("failed to send test payload: %v", err)
		}
		respTime, err := resp.responseTime()
		if err != nil {
			return nil, errors.New("failed to calculate response time to payload: %v", err)
		}

		fmt.Println("response time:", respTime)
		responseTimes[i] = int64(respTime)
	}

	responseTimeData := stats.LoadRawData(responseTimes)
	minResponseTime, err := responseTimeData.Min()
	if err != nil {
		return nil, errors.New("failed to calculate minimum response time: %v", err)
	}
	maxResponseTime, err := responseTimeData.Max()
	if err != nil {
		return nil, errors.New("failed to calculate maximum response time: %v", err)
	}
	responseTimeStdDev, err := responseTimeData.StandardDeviation()
	if err != nil {
		return nil, errors.New("failed to standard deviation of response time: %v", err)
	}
	return &responseBaseline{minResponseTime, maxResponseTime, responseTimeStdDev}, nil
}

// An explanation is provided when the response falls outside the accepted bounds.
func (baseline responseBaseline) withinAcceptedBounds(resp tcpResponse) (_ bool, explanation string, _ error) {
	respTime, err := resp.responseTime()
	if err != nil {
		return false, "", errors.New("failed to calculate response time: %v", err)
	}
	if float64(respTime) < baseline.minResponseTime-baseline.responseTimeStdDev {
		explanation := fmt.Sprintf(
			"response time %v is more than a standard deviation (%v) less than the minimum baseline response time of %v",
			respTime, time.Duration(baseline.responseTimeStdDev), time.Duration(baseline.minResponseTime),
		)
		return false, explanation, nil
	}
	if float64(respTime) > baseline.maxResponseTime+baseline.responseTimeStdDev {
		explanation := fmt.Sprintf(
			"response time %v is more than a standard deviation (%v) greater than the maximum baseline response time of %v",
			respTime, time.Duration(baseline.responseTimeStdDev), time.Duration(baseline.maxResponseTime),
		)
		return false, explanation, nil
	}
	return true, "", nil
}

// Returns the minimum integer in the range [start, end) for which the predicate is true. Assumes:
// 	- end > start
//	- start is > 0
//	- if predicate(i) is true, then predicate(n) is true for all n > i
//	- if predicate(i) is false, then preciate(n) is false for all n < i
// Returns -1 if the predicate is false over the entire range.
// Returns an error immediately if predicate returns an error.
func minBinarySearch(start, end int, predicate func(int) (bool, error)) (_ int, err error) {
	predicateStart, err := predicate(start)
	if err != nil {
		return 0, err
	}
	if predicateStart {
		return start, nil
	}
	predicateEndMinus1, err := predicate(end - 1)
	if err != nil {
		return 0, err
	}
	if !predicateEndMinus1 {
		return -1, nil
	}

	middle := ((end - start) / 2) + start
	predicateMiddle, err := predicate(middle)
	if err != nil {
		return 0, err
	}
	if predicateMiddle {
		lowerResult, err := minBinarySearch(start, middle, predicate)
		if err != nil {
			return 0, err
		}
		if lowerResult != -1 {
			return lowerResult, nil
		}
		return middle, nil
	}
	return minBinarySearch(middle+1, end, predicate)
}