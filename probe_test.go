package probe

import (
	"bytes"
	"net"
	"strings"
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
			if netErr, ok := err.(net.Error); ok && !netErr.Temporary() {
				return
			}
			errChan <- errors.New("accept failed: %v", err)
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			b := make([]byte, s.maxPayloadSize)
			n, err := readPayload(c, b)
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

// Reads from conn into b until conn.Read blocks or returns an error.
func readPayload(conn net.Conn, b []byte) (n int, err error) {
	// There should not be a delay between reads if there is data on the connection.
	const timeout = time.Millisecond

	var currentN int
	for {
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

type testLogger struct {
	t *testing.T
}

func (tl testLogger) Write(b []byte) (int, error) {
	tl.t.Logf("\n%s", string(b))
	return len(b), nil
}

func TestForRandomizedTransport(t *testing.T) {
	t.Parallel()

	const (
		// Pre-configured baseline data.
		minResponseTime = 1 * time.Microsecond
		maxResponseTime = 2 * time.Millisecond
		respTimeStdDev  = 1 * time.Millisecond
		respFlags       = "FIN ACK"
	)

	baseline := ForRandomizedTransportBaseline{
		minResponseTime,
		maxResponseTime,
		respTimeStdDev,
		strings.Split(respFlags, " "),
	}

	t.Run("response time", func(t *testing.T) {
		t.Parallel()

		// This delay at the threshold size is well outside the normal response time (defined by the
		// baseline data).
		atThreshold := func(conn net.Conn) error { time.Sleep(10 * time.Millisecond); return nil }

		FRTHelper(t, baseline, atThreshold)
	})

	t.Run("response flags", func(t *testing.T) {
		t.Parallel()

		// Writing something before hanging up will change the response flags.
		atThreshold := func(conn net.Conn) error { _, err := conn.Write([]byte{0}); return err }

		FRTHelper(t, baseline, atThreshold)
	})
}

func FRTHelper(t *testing.T, baseline ForRandomizedTransportBaseline, atThreshold func(net.Conn) error) {
	t.Helper()

	const (
		network    = "tcp"
		localhost0 = "127.0.0.1:0"

		// This is strategically chosen to appear relatively early in the binary search.
		payloadSizeThreshold = 526

		// This needs to be the same as defined in ForRandomizedTransport.
		maxPayloadSize = 64 * 1024

		// This is the current lower bound for parallelism. Setting this too high can cause
		// artificial test failures as the test server cannot keep up with incoming connections.
		maxParallelism = 10
	)

	baselineBuf := new(bytes.Buffer)
	bd := baselineData{ForRandomizedTransport: &baseline}
	require.NoError(t, bd.write(baselineBuf))

	l, err := net.Listen(network, localhost0)
	require.NoError(t, err)
	defer l.Close()

	serverErrors, done := make(chan error), make(chan struct{})
	go func() {
		for err := range serverErrors {
			select {
			case <-done:
				return
			default:
				t.Fatal("server error:", err)
			}
		}
	}()
	defer close(done)

	s := testRandomizedTransportServer{l, payloadSizeThreshold, maxPayloadSize, atThreshold}
	go s.serve(serverErrors)

	results, err := ForRandomizedTransport(Config{
		Network:        network,
		Address:        s.Addr().String(),
		BaselineData:   baselineBuf,
		Logger:         testLogger{t},
		MaxParallelism: maxParallelism,
	})
	require.NoError(t, err)
	require.True(t, results.Success)

	t.Log(results.Explanation)
	require.Equal(t, payloadSizeThreshold, results.Explanation.(ForRandomizedTransportExplanation).PayloadSizeThreshold)
}
