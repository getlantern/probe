// Package probe offers utilities for actively probing servers. The idea is to probe our own servers
// as a censor would, looking for giveaways that the server is used for circumvention.
package probe

import "time"

// Config for a probe.
type Config struct {
	// Network to use (ala net.Dial).
	Network string

	// Address to probe.
	Address string

	Timeout time.Duration
}

// FailedCheck is a special error type indicating that a probed server failed a check. This can be
// used to distinguish detectability errors from errors rooted in things like network failures.
type FailedCheck interface {
	error
}

// ForRandomizedTransport probes for evidence of a randomized transport like obsf4 or Lampshade.
func ForRandomizedTransport(cfg Config) error {
	// TODO: implement me!
	return nil
}
