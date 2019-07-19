// Package probe offers utilities for actively probing servers. The idea is to probe our own servers
// as a censor would, looking for giveaways that the server is used for circumvention.
package probe

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
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
//	- memoize results in minBinarySearch
// 	- try parallelizing baseline measurement
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

	Logger io.Writer

	// TODO: support timeout
}

func (c Config) logger() io.Writer {
	if c.Logger == nil {
		return ioutil.Discard
	}
	return c.Logger
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
		baseline *forRandomizedTransportBaseline
		err      error
		results  Results
	)

	if cfg.BaselineData != nil {
		bd, err := readBaselineData(cfg.BaselineData)
		if err != nil {
			return nil, errors.New("failed to read baseline data: %v", err)
		}
		if bd.ForRandomizedTransport != nil && bd.ForRandomizedTransport.complete() {
			fmt.Fprintln(cfg.logger(), "using pre-configured baseline")
			baseline = bd.ForRandomizedTransport
		}
	}

	if baseline == nil {
		fmt.Fprintln(cfg.logger(), "establishing baseline")

		bd := new(baselineData)
		bd.ForRandomizedTransport, err = establishRandomizedTransportBaseline(cfg, baselinePackets)
		if err != nil {
			return nil, errors.New("failed to establish baseline response: %v", err)
		}
		baseline = bd.ForRandomizedTransport
		buf := new(bytes.Buffer)
		if err := bd.write(buf); err != nil {
			return nil, errors.New("failed to write baseline data: %v", err)
		}
		results.BaselineData = buf

		fmt.Fprintf(
			cfg.logger(),
			"baseline response:\n\tmin response time: %v\n\tmax response time: %v\n\tresponse time standard deviation: %v\n",
			time.Duration(baseline.MinResponseTime),
			time.Duration(baseline.MaxResponseTime),
			time.Duration(baseline.ResponseTimeStdDev),
		)
	}

	respWithinBoundsFull := func(payloadSize int) (_ bool, explanation string, _ error) {
		fmt.Fprintf(cfg.logger(), "trying %d byte payload\n", payloadSize)

		payload := make([]byte, payloadSize)
		_, err := rand.Read(payload)
		if err != nil {
			return false, "", errors.New("failed to generate payload: %v", err)
		}

		resp, err := sendTCPPayload(cfg, payload)
		if err != nil {
			return false, "", errors.New("failed to send payload: %v", err)
		}

		return baseline.withinAcceptedBounds(*resp)
	}
	respOutOfBounds := func(payloadSize int) (bool, error) {
		ok, _, err := respWithinBoundsFull(payloadSize)
		// TODO: this is clunky
		return !ok, err
	}

	fmt.Fprintln(cfg.logger(), "trying varying payload sizes")

	s := minBinarySearch{respOutOfBounds, map[int]bool{}}
	payloadSizeThreshold, err := s.search(2, maxPayloadSize)
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
	return firstResponse.Timestamp.Sub(firstSent.Timestamp), nil
}

// Establishes a connection and sends the input payload. Returns all packets sent in response. The
// response is guaranteed to have at least one packet.
func sendTCPPayload(cfg Config, payload []byte) (*tcpResponse, error) {
	// TODO: currently assuming in-order packet capture - vet or fix this

	conn, err := probednet.Dial(cfg.Network, cfg.Address)
	if err != nil {
		return nil, errors.New("failed to dial address: %v", err)
	}
	linkLayer := expectedLinkLayer(conn.RemoteAddr())

	capturedPackets := []pktutil.TransportPacket{}
	captureComplete := make(chan struct{})
	captureErrors := make(chan error)
	go func() {
		defer close(captureComplete)
		fmt.Fprintln(cfg.logger(), "================= captured packets ====================")
		for pkt := range conn.CapturedPackets() {
			decoded, err := pktutil.DecodeTransportPacket(pkt.Data, linkLayer)
			if err != nil {
				captureErrors <- errors.New("failed to decode captured packet: %v", err)
				return
			}
			decoded.Timestamp = pkt.Timestamp
			capturedPackets = append(capturedPackets, *decoded)

			fmt.Fprintln(cfg.logger(), decoded.Pprint())
		}
	}()
	go func() {
		for err := range conn.CaptureErrors() {
			captureErrors <- err
		}
	}()

	// Because we are sometimes triggering error states on the servers we write to, we expect to run
	// into certain errors.
	acceptableWriteError := func(n int, err error) bool {
		// A broken pipe or incorrect protocol error indicates that the connection has been reset.
		// We expect some servers to do this for large payloads.
		if strings.Contains(err.Error(), "broken pipe") {
			return true
		}
		if strings.Contains(err.Error(), "protocol wrong type for socket") {
			return true
		}
		return false
	}

	n, err := conn.Write(payload)
	if err != nil && !acceptableWriteError(n, err) {
		conn.Close()

		// Wait for capture to complete so that relevant packets get logged.
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

	var (
		payloadPkts  []pktutil.TransportPacket
		responsePkts []pktutil.TransportPacket
	)
	for _, pkt := range capturedPackets {
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
