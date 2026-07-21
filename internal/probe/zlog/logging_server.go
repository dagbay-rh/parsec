package zlog

import (
	"context"
	"time"

	"github.com/rs/zerolog"

	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/server"
)

var _ server.LifecycleObserver = (*LoggingServerLifecycleObserver)(nil)

// LoggingServerLifecycleObserver logs server lifecycle events via zerolog.
type LoggingServerLifecycleObserver struct {
	server.NoOpLifecycleObserver
	logger zerolog.Logger
	clock  clock.Clock
}

func NewLoggingServerLifecycleObserver(logger zerolog.Logger, opts ...Option) *LoggingServerLifecycleObserver {
	cfg := resolveOptions(opts)
	return &LoggingServerLifecycleObserver{logger: logger, clock: cfg.clk}
}

func (o *LoggingServerLifecycleObserver) GRPCServeFailed(err error) {
	o.logger.Error().Err(err).Msg("gRPC server error")
}

func (o *LoggingServerLifecycleObserver) HTTPServeFailed(err error) {
	o.logger.Error().Err(err).Msg("HTTP server error")
}

func (o *LoggingServerLifecycleObserver) StopStarted(ctx context.Context) (context.Context, server.StopProbe) {
	return ctx, &loggingStopProbe{
		logger:    o.logger,
		startTime: o.clock.Now(),
		clock:     o.clock,
	}
}

type loggingStopProbe struct {
	server.NoOpStopProbe
	logger    zerolog.Logger
	startTime time.Time
	clock     clock.Clock
}

func (p *loggingStopProbe) End() {
	p.logger.Debug().
		Dur("duration", p.clock.Since(p.startTime)).
		Msg("server stopped")
}
