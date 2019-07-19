package probe

import (
	"encoding/gob"
	"fmt"
	"io"
	"time"

	"github.com/montanaflynn/stats"

	"github.com/getlantern/errors"
)

// baselineData is the container for all baseline data. This is always the structure encoded in
// Config.BaselineData or Results.BaselineData.
type baselineData struct {
	ForRandomizedTransport *forRandomizedTransportBaseline
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

type forRandomizedTransportBaseline struct {
	MinResponseTime, MaxResponseTime, ResponseTimeStdDev time.Duration
}

func establishRandomizedTransportBaseline(cfg Config, baselinePackets int) (*forRandomizedTransportBaseline, error) {
	var testPayload = []byte{1}

	responseTimes := make([]int64, baselinePackets)
	// TODO: track responses: payloads, flags, how many packets
	for i := 0; i < baselinePackets; i++ {
		resp, err := sendTCPPayload(cfg, testPayload)
		if err != nil {
			return nil, errors.New("failed to send test payload: %v", err)
		}
		respTime, err := resp.responseTime()
		if err != nil {
			return nil, errors.New("failed to calculate response time to payload: %v", err)
		}

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
	return &forRandomizedTransportBaseline{
		time.Duration(minResponseTime),
		time.Duration(maxResponseTime),
		// Truncating the std dev should be fine as we're only losing fractions of a nanosecond.
		time.Duration(responseTimeStdDev),
	}, nil
}

// An explanation is provided when the response falls outside the accepted bounds.
func (b *forRandomizedTransportBaseline) withinAcceptedBounds(resp tcpResponse) (_ bool, explanation string, _ error) {
	respTime, err := resp.responseTime()
	if err != nil {
		return false, "", errors.New("failed to calculate response time: %v", err)
	}
	if respTime < b.MinResponseTime-b.ResponseTimeStdDev {
		explanation := fmt.Sprintf(
			"response time %v is more than a standard deviation (%v) less than the minimum baseline response time of %v",
			respTime, time.Duration(b.ResponseTimeStdDev), time.Duration(b.MinResponseTime),
		)
		return false, explanation, nil
	}
	if respTime > b.MaxResponseTime+b.ResponseTimeStdDev {
		explanation := fmt.Sprintf(
			"response time %v is more than a standard deviation (%v) greater than the maximum baseline response time of %v",
			respTime, time.Duration(b.ResponseTimeStdDev), time.Duration(b.MaxResponseTime),
		)
		return false, explanation, nil
	}
	return true, "", nil
}

func (b forRandomizedTransportBaseline) complete() bool {
	return b.MinResponseTime != 0 && b.MaxResponseTime != 0 && b.ResponseTimeStdDev != 0
}
