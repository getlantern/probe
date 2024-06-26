// Package probe offers utilities for actively probing servers. The idea is to probe our own servers
// as a censor would, looking for giveaways that the server is used for circumvention.
package probe

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

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

	// BaselineData is any data saved from a previously run probe. Providing baseline data will
	// reduce the time needed for a probe test.
	BaselineData io.Reader

	// MaxParallelism is the maximum number of goroutines spawned during a probe. This number is
	// approximate and will be honored on a best-effort basis. A value <= 0 indicates that there is
	// no limit to parallelism.
	MaxParallelism int

	// ResponseTimeout is the time the probe allows the server to respond to each probe payload.
	// After this duration has passed, the server is determined to have no response. A value <= 0
	// indicates that there should be no timeout.
	ResponseTimeout time.Duration

	Logger io.Writer
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
	Explanation fmt.Stringer

	// BaselineData encodes the baseline against which the probe's test was run. BaselineData is
	// non-nil iff the probe created baseline data outside of what was provided by Config.
	BaselineData io.Reader
}

// ForRandomizedTransportExplanation is the concrete type returned as the Results.Explanation when
// a ForRandomizedTransport probe returns Results.Success.
type ForRandomizedTransportExplanation struct {
	// PayloadSizeThreshold is the payload size at which the behavior of the server changed.
	PayloadSizeThreshold int

	// ResponseTime is the time the server took to respond to a payload of the threshold size.
	ResponseTime time.Duration

	// ResponseFlags is the set of TCP flags seen on the first response packet. The first response
	// packet is defined as the first packet received from the server which (a) was sent after the
	// first client payload packet and (b) was more than a simple ACK.
	ResponseFlags []string

	// Baseline against which responses were compared.
	Baseline ForRandomizedTransportBaseline
}

func (e ForRandomizedTransportExplanation) String() string {
	buf := new(bytes.Buffer)
	ok, explanation := e.Baseline.withinAcceptedBounds(e.ResponseTime)
	if !ok {
		fmt.Fprintf(
			buf,
			"response to payload of %d bytes fell outside the bounds established by the baseline: %s",
			e.PayloadSizeThreshold,
			explanation,
		)
		return buf.String()
	}
	ok, explanation = e.Baseline.flagsMatchExpected(e.ResponseFlags)
	if !ok {
		fmt.Fprintf(
			buf,
			"response to payload of %d bytes fell outside the bounds established by the baseline: %s",
			e.PayloadSizeThreshold,
			explanation,
		)
		return buf.String()
	}
	return ""
}

// ForRandomizedTransport probes for evidence of a randomized transport like Lampshade.
func ForRandomizedTransport(cfg Config) (*Results, error) {

	// 1. Establish a baseline response using single-byte payloads.
	// 2. Using a binary search (up to a maximum payload size), find the payload length at which the
	//    response differs from the baseline.
	// 3. If the response never changes up to the maximum payload size, the check passes.

	const (
		maxPayloadSize  = 64 * 1024
		baselinePackets = 100
	)

	var (
		baseline *ForRandomizedTransportBaseline
		err      error
		results  Results
	)

	switch cfg.Network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, errors.New("randomized transport probe not implemented for this network")
	}

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

		fmt.Fprintln(cfg.logger(), *baseline)
	}

	numSearchRoutines := cfg.MaxParallelism
	if numSearchRoutines <= 0 {
		numSearchRoutines = baselinePackets
	} else if numSearchRoutines < 4 {
		// There is currently a lower bound on the number of search routines.
		numSearchRoutines = 4
	}

	var (
		explanations            = make(chan ForRandomizedTransportExplanation, numSearchRoutines)
		explanationsMap         = map[int]ForRandomizedTransportExplanation{}
		explanationsMapComplete = make(chan struct{})
	)
	go func() {
		for e := range explanations {
			explanationsMap[e.PayloadSizeThreshold] = e
		}
		close(explanationsMapComplete)
	}()

	tcpSender := tcpSender{cfg: cfg}
	respOutOfBounds := func(payloadSize int) (bool, error) {
		fmt.Fprintf(cfg.logger(), "trying %d byte payload\n", payloadSize)

		payload := make([]byte, payloadSize)
		_, err := rand.Read(payload)
		if err != nil {
			return false, errors.New("failed to generate payload: %v", err)
		}

		resp, err := tcpSender.send(payload)
		if err != nil {
			return false, errors.New("failed to send payload: %v", err)
		}

		respTime, err := resp.responseTime()
		if err != nil {
			return false, errors.New("failed to calculate response time: %v", err)
		}

		var flags []string
		if firstNonACK := resp.firstNonACK(); firstNonACK != nil {
			flags = flagsToStrings(firstNonACK.Flags())
		}

		expectedFlags, _ := baseline.flagsMatchExpected(flags)
		withinTimeBounds, _ := baseline.withinAcceptedBounds(respTime)
		if !expectedFlags || !withinTimeBounds {
			explanations <- ForRandomizedTransportExplanation{
				payloadSize, respTime, flags, *baseline,
			}
			return true, nil
		}
		return false, nil
	}

	fmt.Fprintln(cfg.logger(), "trying varying payload sizes")

	s := newParallelSearch(respOutOfBounds, numSearchRoutines)
	payloadSizeThreshold, err := s.search(2, maxPayloadSize)
	close(explanations)
	if err != nil {
		return nil, errors.New("search for payload size threshold failed: %v", err)
	}
	if payloadSizeThreshold > 0 {
		<-explanationsMapComplete
		results.Success = true
		results.Explanation = explanationsMap[payloadSizeThreshold]
	} else {
		results.Success = false
	}
	return &results, nil
}

type tcpResponse struct {
	sent    []pktutil.TransportPacket
	packets []pktutil.TransportPacket
}

// Returns nil if no response was received.
func (r tcpResponse) firstNonACK() *pktutil.TransportPacket {
	if len(r.packets) < 1 {
		return nil
	}

	for _, pkt := range r.packets {
		if pkt.HasAnyFlags(
			pktutil.SYN, pktutil.FIN, pktutil.URG, pktutil.PSH,
			pktutil.RST, pktutil.ECE, pktutil.CWR, pktutil.NS,
		) {
			return &pkt
		}
	}
	return nil
}

// We define the respone time as the time between the last packet we sent and the first packet we
// received with any flag other than ACK. Returns the maximum duration if no response was received.
func (r tcpResponse) responseTime() (time.Duration, error) {
	if len(r.sent) < 1 {
		return 0, errors.New("no sent packets")
	}

	firstSent, firstResponse := r.sent[0], r.firstNonACK()
	if firstResponse == nil {
		return time.Duration(math.MaxInt64), nil
	}
	if firstSent.Timestamp.IsZero() || firstResponse.Timestamp.IsZero() {
		return 0, errors.New("no timestamps on captured packets")
	}
	return firstResponse.Timestamp.Sub(firstSent.Timestamp), nil
}

type tcpSender struct {
	cfg      Config
	dialLock sync.Mutex
}

// Establishes a connection and sends the input payload.
func (s *tcpSender) send(p []byte) (*tcpResponse, error) {
	s.dialLock.Lock()
	conn, err := probednet.Dial(s.cfg.Network, s.cfg.Address)
	s.dialLock.Unlock()
	if err != nil {
		return nil, errors.New("failed to dial address: %v", err)
	}
	linkLayer := expectedLinkLayer(conn.RemoteAddr())

	capturedPackets := []pktutil.TransportPacket{}
	captureComplete := make(chan struct{})
	captureErrors := make(chan error)
	go func() {
		defer close(captureComplete)
		fmt.Fprintln(s.cfg.logger(), "================= captured packets ====================")
		for pkt := range conn.CapturedPackets() {
			decoded, err := pktutil.DecodeTransportPacket(pkt.Data, linkLayer)
			if err != nil {
				captureErrors <- errors.New("failed to decode captured packet: %v", err)
				return
			}
			decoded.Timestamp = pkt.Timestamp
			capturedPackets = append(capturedPackets, *decoded)

			fmt.Fprintln(s.cfg.logger(), decoded.Pprint())
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
		if n == 0 {
			return false
		}

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

	n, err := conn.Write(p)
	if err != nil && !acceptableWriteError(n, err) {
		conn.Close()

		// Wait for capture to complete so that relevant packets get logged.
		<-captureComplete

		return nil, errors.New("failed to write payload: %v", err)
	}

	if s.cfg.ResponseTimeout > 0 {
		conn.SetReadDeadline(time.Now().Add(s.cfg.ResponseTimeout))
	}

	// Wait for a response.
	for {
		_, err := conn.Read(make([]byte, 1024))
		if err == nil {
			break
		}
		netErr, ok := err.(net.Error)
		if ok && netErr.Timeout() {
			break
		}
		if ok && netErr.Temporary() {
			continue
		}
		// We don't care about non-temporary errors.
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
		// We don't count any packets after our own FIN (whether this FIN is a result of us closing
		// the connection or a FIN ACK as a result of the peer closing the connection).
		if pkt.DestinedFor(conn.RemoteAddr()) && pkt.HasAllFlags(pktutil.FIN) {
			break
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
