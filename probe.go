// Package probe offers utilities for actively probing servers. The idea is to probe our own servers
// as a censor would, looking for giveaways that the server is used for circumvention.
package probe

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/getlantern/errors"
	"github.com/getlantern/probednet"
	"github.com/getlantern/probednet/pktutil"
)

// TODO:
//	- add logger to config
//	- memoize results in minBinarySearch
//	- analyze content of response packets

// Config for a probe.
type Config struct {
	// Network to use (ala net.Dial).
	Network string

	// Address to probe.
	Address string

	// BaselineData is any data saved from a previously run probe. Providing baseline data will
	// reduce the time needed for a probe test.
	BaselineData io.Reader

	// TODO: support timeout
}

// Results of a probe.
type Results struct {
	// Success reports whether the probe found what it was looking for. In most cases, you want this
	// to be false. True means that the probe was able to identify the server as a circumvention
	// tool.
	Success bool

	// An explanation is provided when Success is true.
	Explanation string

	// BaselineData encodes the baseline against which the probe's test was run. BaselineData is
	// non-nil iff the probe created baseline data outside of what was provided by Config.
	BaselineData io.Reader
}

// ForRandomizedTransport probes for evidence of a randomized transport like obsf4 or Lampshade.
func ForRandomizedTransport(cfg Config) (*Results, error) {

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

	var (
		baseline *randomizedProbeBaseline
		err      error
		results  Results
	)

	if cfg.BaselineData == nil {
		fmt.Println("establishing baseline")

		baseline, err = establishRandomizedProbeBaseline(cfg, baselinePackets)
		if err != nil {
			return nil, errors.New("failed to establish baseline response: %v", err)
		}
		buf := new(bytes.Buffer)
		if err := gob.NewEncoder(buf).Encode(baseline); err != nil {
			return nil, errors.New("failed to encode baseline data: %v", err)
		}
		results.BaselineData = buf

		fmt.Printf(
			"baseline response:\n\tmin response time: %v\n\tmax response time: %v\n\tresponse time standard deviation: %v\n",
			time.Duration(baseline.MinResponseTime),
			time.Duration(baseline.MaxResponseTime),
			time.Duration(baseline.ResponseTimeStdDev),
		)
	} else {
		fmt.Println("using pre-configured baseline")

		baseline = new(randomizedProbeBaseline)
		if err := gob.NewDecoder(cfg.BaselineData).Decode(baseline); err != nil {
			return nil, errors.New("failed to decode baseline data: %v", err)

		}
	}

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

		return baseline.withinAcceptedBounds(*resp)
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
		return nil, errors.New("search for payload size threshold failed: %v", err)
	}
	if payloadSizeThreshold > 0 {
		results.Success = true
		results.Explanation = fmt.Sprintf(
			"response to payload of %d bytes fell outside bounds established by baseline",
			payloadSizeThreshold,
		)
		// TODO: get the explanation from the actual test
		_, additionalExplanation, _ := respWithinBoundsFull(payloadSizeThreshold)
		if results.Explanation != "" {
			results.Explanation = fmt.Sprintf("%s: %s", results.Explanation, additionalExplanation)
		}
	} else {
		results.Success = false
	}
	return &results, nil
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
	linkLayer := expectedLinkLayer(conn.RemoteAddr())

	capturedPackets := []probednet.Packet{}
	captureComplete := make(chan struct{})
	captureErrors := make(chan error)
	go func() {
		// debugging
		fmt.Println("================= captured packets ====================")

		for pkt := range conn.CapturedPackets() {
			capturedPackets = append(capturedPackets, pkt)

			// debugging
			decoded, err := pktutil.DecodeTransportPacket(pkt.Data, linkLayer)
			if err != nil {
				fmt.Println("decoding error:", err)
			} else {
				decoded.Timestamp = pkt.Timestamp
				fmt.Println(decoded.Pprint())
			}
		}
		close(captureComplete)
	}()
	go func() {
		for err := range conn.CaptureErrors() {
			captureErrors <- err
		}
	}()

	// Because we are sometimes triggering error states on the servers we write to, we expect to run
	// into certain errors.
	acceptableWriteError := func(n int, err error) bool {
		// If we didn't write any bytes successfully, the write was a failure.
		if n == 0 {
			return false
		}
		// A broken pipe partway through a write indicates that the connection has been reset. We
		// expect some servers to do this for large payloads.
		if strings.Contains(err.Error(), "broken pipe") {
			return true
		}
		// An incorrect protocol error partway through a write indicates that the connection has
		// been reset.
		if strings.Contains(err.Error(), "protocol wrong type for socket") {
			return true
		}
		return false
	}

	n, err := conn.Write(payload)
	if err != nil && !acceptableWriteError(n, err) {
		conn.Close()

		// debugging
		<-captureComplete

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

	// fmt.Println("================== captured packets ===================")

	pkts := make([]pktutil.TransportPacket, len(capturedPackets))
	for i, pkt := range capturedPackets {
		decoded, err := pktutil.DecodeTransportPacket(pkt.Data, linkLayer)
		if err != nil {
			return nil, errors.New("failed to decode packet: %v", err)
		}
		decoded.Timestamp = pkt.Timestamp
		pkts[i] = *decoded

		// fmt.Println(decoded.Pprint())
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

func expectedLinkLayer(addr net.Addr) gopacket.LayerType {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		panic(fmt.Sprint("unexpected failure to parse address: ", err))
	}
	if !net.ParseIP(host).IsLoopback() {
		return layers.LayerTypeEthernet
	}
	if runtime.GOOS == "linux" {
		return layers.LayerTypeEthernet
	}
	return layers.LayerTypeLoopback
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
