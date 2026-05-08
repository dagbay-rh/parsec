package zlog

import (
	"context"
	"time"

	"github.com/rs/zerolog"

	"github.com/project-kessel/parsec/internal/server"
)

var _ server.LifecycleObserver = (*LoggingServerLifecycleObserver)(nil)

// LoggingServerLifecycleObserver logs server lifecycle events via zerolog.
type LoggingServerLifecycleObserver struct {
	server.NoOpLifecycleObserver
	logger zerolog.Logger
}

func NewLoggingServerLifecycleObserver(logger zerolog.Logger) *LoggingServerLifecycleObserver {
	return &LoggingServerLifecycleObserver{logger: logger}
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
		startTime: time.Now(),
	}
}

type loggingStopProbe struct {
	server.NoOpStopProbe
	logger    zerolog.Logger
	startTime time.Time
}

func (p *loggingStopProbe) End() {
	p.logger.Debug().
		Dur("duration", time.Since(p.startTime)).
		Msg("server stopped")
}
