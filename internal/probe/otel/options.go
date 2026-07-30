package otel

import "github.com/project-kessel/parsec/internal/clock"

// ObserverOption configures optional parameters for [NewObserver].
type ObserverOption func(*observerOptions)

type observerOptions struct {
	clk clock.Clock
}

// WithClock sets the clock used for timing operations.
// If not provided, [NewObserver] defaults to [clock.NewSystemClock].
func WithClock(clk clock.Clock) ObserverOption {
	return func(o *observerOptions) {
		if clk != nil {
			o.clk = clk
		}
	}
}

func resolveObserverOptions(opts []ObserverOption) observerOptions {
	o := observerOptions{clk: clock.NewSystemClock()}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}
