package zlog

import "github.com/project-kessel/parsec/internal/clock"

// Option configures optional parameters for zlog observer constructors.
type Option func(*options)

type options struct {
	clk clock.Clock
}

// WithClock sets the clock used for timing operations.
// If not provided, constructors default to [clock.NewSystemClock].
func WithClock(clk clock.Clock) Option {
	return func(o *options) {
		if clk != nil {
			o.clk = clk
		}
	}
}

func resolveOptions(opts []Option) options {
	o := options{clk: clock.NewSystemClock()}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}
