package probe

import (
	"fmt"
	"time"

	"github.com/montanaflynn/stats"

	"github.com/getlantern/errors"
)

type randomizedProbeBaseline struct {
	MinResponseTime    float64
	MaxResponseTime    float64
	ResponseTimeStdDev float64
}

func establishRandomizedProbeBaseline(cfg Config, baselinePackets int) (*randomizedProbeBaseline, error) {
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
	return &randomizedProbeBaseline{minResponseTime, maxResponseTime, responseTimeStdDev}, nil
}

// An explanation is provided when the response falls outside the accepted bounds.
func (b *randomizedProbeBaseline) withinAcceptedBounds(resp tcpResponse) (_ bool, explanation string, _ error) {
	respTime, err := resp.responseTime()
	if err != nil {
		return false, "", errors.New("failed to calculate response time: %v", err)
	}
	if float64(respTime) < b.MinResponseTime-b.ResponseTimeStdDev {
		explanation := fmt.Sprintf(
			"response time %v is more than a standard deviation (%v) less than the minimum baseline response time of %v",
			respTime, time.Duration(b.ResponseTimeStdDev), time.Duration(b.MinResponseTime),
		)
		return false, explanation, nil
	}
	if float64(respTime) > b.MaxResponseTime+b.ResponseTimeStdDev {
		explanation := fmt.Sprintf(
			"response time %v is more than a standard deviation (%v) greater than the maximum baseline response time of %v",
			respTime, time.Duration(b.ResponseTimeStdDev), time.Duration(b.MaxResponseTime),
		)
		return false, explanation, nil
	}
	return true, "", nil
}
