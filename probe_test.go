package probe

import (
	"fmt"
	"net"
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
			n, err := c.Read(b)
			if err != nil {
				errChan <- errors.New("read failed: %v", err)
				return
			}
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

func TestForRandomizedTransport(t *testing.T) {
	t.Parallel()

	const (
		network              = "tcp"
		localhost0           = "127.0.0.1:0"
		payloadSizeThreshold = 128

		// This needs to be the same as defined in ForRandomizedTransport.
		maxPayloadSize = 1024 * 1024
	)

	// At the threshold size, we introduce a brief delay.
	atThreshold := func(conn net.Conn) error { fmt.Println("atThreshold called"); time.Sleep(time.Second); return nil }

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
		Network: network,
		Address: s.Addr().String(),
	})
	require.NoError(t, err)
	require.True(t, results.Success)

	// TODO: check that threshold was correct
}

func TestMinBinarySearch(t *testing.T) {
	for start := 0; start <= 7; start++ {
		for end := start + 1; end <= 8; end++ {
			for n := start; n <= end; n++ {
				expected := n
				if n == end {
					expected = -1
				}
				actual, err := minBinarySearch(start, end, func(i int) (bool, error) { return i >= n, nil })
				require.NoError(t, err)
				require.Equal(
					t, expected, actual,
					"start: %d, end: %d, predicate: i >= %d",
					start, end, n,
				)
			}
		}
	}
}
