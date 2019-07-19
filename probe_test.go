package probe

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/getlantern/errors"
)

// A test server mimicking behavior commonly seen in randomized transports. Upon receiving packets
// up to some threshold size, the server immediately closes the connection. At the threshold size,
// the behavior changes. In practice, a randomized transport is more likely to immediately close a
// connection when the payload is over some threshold size, rather than under. We flip that
// behavior here as (a) this makes the test a lot faster and (b) the important thing is just that
// the behavior changes.
type testRandomizedTransportServer struct {
	net.Listener
	payloadSizeThreshold int
	maxPayloadSize       int
	atThreshold          func(conn net.Conn) error
}

func (s testRandomizedTransportServer) serve(errChan chan<- error) {
	for {
		conn, err := s.Accept()
		if err != nil {
			errChan <- errors.New("accept failed: %v", err)
		}
		go func(c net.Conn) {
			defer c.Close()
			b := make([]byte, s.maxPayloadSize)
			n, err := readPayload(c, b)
			if err != nil {
				errChan <- errors.New("read failed: %v", err)
				return
			}
			fmt.Printf("read %d bytes\n", n)
			if n >= s.payloadSizeThreshold {
				err := s.atThreshold(c)
				if err != nil {
					errChan <- errors.New("threshold function failed: %v", err)
					return
				}
			}
		}(conn)
	}
}

// Reads from conn into b until conn.Read blocks or returns an error.
func readPayload(conn net.Conn, b []byte) (n int, err error) {
	// There should not be a delay between reads if there is data on the connection.
	const timeout = 100 * time.Microsecond

	var currentN int
	for {
		fmt.Println("reading")
		conn.SetReadDeadline(time.Now().Add(timeout))
		currentN, err = conn.Read(b[n:])
		n = n + currentN
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return n, nil
			}
			return
		}
	}
}

func TestForRandomizedTransport(t *testing.T) {
	t.Parallel()

	const (
		network    = "tcp"
		localhost0 = "127.0.0.1:0"

		// This is strategically chosen to appear relatively early in the binary search.
		payloadSizeThreshold = 524289

		// This needs to be the same as defined in ForRandomizedTransport.
		maxPayloadSize = 1024 * 1024

		// Pre-configured baseline data.
		minResponseTime = 200 * time.Microsecond
		maxResponseTime = 1500 * time.Microsecond
		respTimeStdDev  = 500 * time.Microsecond

		// The delay at the threshold size is well outside the normal response time (defined by the
		// baseline data).
		delayAtThreshold = 10 * time.Millisecond
	)

	baselineBuf := new(bytes.Buffer)
	bd := baselineData{
		ForRandomizedTransport: &ForRandomizedTransportBaseline{
			minResponseTime, maxResponseTime, respTimeStdDev,
		},
	}
	require.NoError(t, bd.write(baselineBuf))

	// At the threshold size, we introduce a brief delay.
	atThreshold := func(conn net.Conn) error { fmt.Println("atThreshold called"); time.Sleep(delayAtThreshold); return nil }

	l, err := net.Listen(network, localhost0)
	require.NoError(t, err)
	defer l.Close()

	serverErrors, done := make(chan error), make(chan struct{})
	go func() {
		select {
		case err := <-serverErrors:
			t.Fatal("server error:", err)
		case <-done:
		}
	}()

	s := testRandomizedTransportServer{l, payloadSizeThreshold, maxPayloadSize, atThreshold}
	go s.serve(serverErrors)

	results, err := ForRandomizedTransport(Config{
		Network:      network,
		Address:      s.Addr().String(),
		BaselineData: baselineBuf,
		Logger:       os.Stdout,
	})
	require.NoError(t, err)
	require.True(t, results.Success)
	require.Equal(t, payloadSizeThreshold, results.Explanation.(ForRandomizedTransportExplanation).PayloadSizeThreshold)
}
