package probe

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/montanaflynn/stats"

	"github.com/getlantern/errors"
	"github.com/getlantern/probednet/pktutil"
)

// baselineData is the container for all baseline data. This is always the structure encoded in
// Config.BaselineData or Results.BaselineData.
type baselineData struct {
	ForRandomizedTransport *ForRandomizedTransportBaseline
}

func readBaselineData(r io.Reader) (*baselineData, error) {
	bd := new(baselineData)
	if err := gob.NewDecoder(r).Decode(bd); err != nil {
		return nil, err
	}
	return bd, nil
}

func (bd baselineData) write(w io.Writer) error {
	return gob.NewEncoder(w).Encode(bd)
}

// ForRandomizedTransportBaseline represents the baseline used by ForRandomizedTransport.
type ForRandomizedTransportBaseline struct {
	MinResponseTime, MaxResponseTime, ResponseTimeStdDev time.Duration

	// ResponseFlags is the set of TCP flags seen on the first response packet. The first response
	// packet is defined as the first packet received from the server which (a) was sent after the
	// first client payload packet and (b) was more than a simple ACK.
	//
	// In the case where the set of flags in the first response packet is not consistent, this will
	// be an empty, non-nil slice.
	ResponseFlags []string
}

func establishRandomizedTransportBaseline(cfg Config, baselinePackets int) (*ForRandomizedTransportBaseline, error) {
	var testPayload = []byte{1}

	var (
		timesChan = make(chan int64, baselinePackets)
		flagsChan = make(chan []string, baselinePackets)
		errorChan = make(chan error, baselinePackets)
		wg        = new(sync.WaitGroup)
	)

	sendTestPayload := func() {
		defer wg.Done()

		resp, err := sendTCPPayload(cfg, testPayload)
		if err != nil {
			errorChan <- errors.New("failed to send test payload: %v", err)
			return
		}

		respTime, err := resp.responseTime()
		if err != nil {
			errorChan <- errors.New("failed to calculate response time to payload: %v", err)
			return
		}
		timesChan <- int64(respTime)

		firstNonACK, err := resp.firstNonACK()
		if err != nil {
			errorChan <- errors.New("failed to analyze response flags: %v", err)
		}
		flagsChan <- flagsToStrings(firstNonACK.Flags())
	}

	for i := 0; i < baselinePackets; i++ {
		wg.Add(1)
		go sendTestPayload()
	}
	wg.Wait()

	select {
	case err := <-errorChan:
		return nil, err
	default:
	}

	close(timesChan)
	close(flagsChan)
	close(errorChan)

	responseTimes := []int64{}
	for respTime := range timesChan {
		responseTimes = append(responseTimes, respTime)
	}

	responseFlags := <-flagsChan
	for currentFlags := range flagsChan {
		if !stringSlicesEqual(responseFlags, currentFlags) {
			// Response flags are not consistent.
			responseFlags = []string{}
			break
		}
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

	return &ForRandomizedTransportBaseline{
		time.Duration(minResponseTime),
		time.Duration(maxResponseTime),
		// Truncating the std dev should be fine as we're only losing fractions of a nanosecond.
		time.Duration(responseTimeStdDev),
		responseFlags,
	}, nil
}

// An explanation is provided when the response falls outside the accepted bounds.
func (b ForRandomizedTransportBaseline) withinAcceptedBounds(respTime time.Duration) (_ bool, explanation string) {
	if respTime < b.MinResponseTime-b.ResponseTimeStdDev {
		explanation := fmt.Sprintf(
			"response time %v is more than a standard deviation (%v) less than the minimum baseline response time of %v",
			respTime, time.Duration(b.ResponseTimeStdDev), time.Duration(b.MinResponseTime),
		)
		return false, explanation
	}
	if respTime > b.MaxResponseTime+b.ResponseTimeStdDev {
		explanation := fmt.Sprintf(
			"response time %v is more than a standard deviation (%v) greater than the maximum baseline response time of %v",
			respTime, time.Duration(b.ResponseTimeStdDev), time.Duration(b.MaxResponseTime),
		)
		return false, explanation
	}
	return true, ""
}

func (b ForRandomizedTransportBaseline) flagsMatchExpected(flags []string) bool {
	if len(b.ResponseFlags) == 0 {
		// No definition of expected flags - anything goes.
		return true
	}
	return stringSlicesEqual(b.ResponseFlags, flags)
}

func (b ForRandomizedTransportBaseline) complete() bool {
	return b.MinResponseTime != 0 &&
		b.MaxResponseTime != 0 &&
		b.ResponseTimeStdDev != 0 &&
		b.ResponseFlags != nil
}

func (b ForRandomizedTransportBaseline) String() string {
	buf := new(bytes.Buffer)
	fmt.Fprintf(
		buf,
		"baseline response:\n\tmin response time: %v\n\tmax response time: %v\n\tresponse time standard deviation: %v",
		time.Duration(b.MinResponseTime),
		time.Duration(b.MaxResponseTime),
		time.Duration(b.ResponseTimeStdDev),
	)
	if len(b.ResponseFlags) > 0 {
		fmt.Fprint(buf, "\n\tflags: ")
		for _, f := range b.ResponseFlags {
			fmt.Fprint(buf, f, " ")
		}
	}
	return buf.String()
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func flagsToStrings(flags []pktutil.TCPFlag) []string {
	strings := make([]string, len(flags))
	for i := range flags {
		strings[i] = string(flags[i])
	}
	return strings
}
