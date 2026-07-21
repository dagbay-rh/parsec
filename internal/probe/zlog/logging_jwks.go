package zlog

import (
	"context"
	"time"

	"github.com/rs/zerolog"

	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/server"
)

var _ server.JWKSObserver = (*LoggingJWKSObserver)(nil)

// LoggingJWKSObserver logs JWKS cache lifecycle events via zerolog.
type LoggingJWKSObserver struct {
	server.NoOpJWKSObserver
	logger zerolog.Logger
	clock  clock.Clock
}

func NewLoggingJWKSObserver(logger zerolog.Logger, opts ...Option) *LoggingJWKSObserver {
	cfg := resolveOptions(opts)
	return &LoggingJWKSObserver{logger: logger, clock: cfg.clk}
}

func (o *LoggingJWKSObserver) InitPopulationStarted(ctx context.Context) (context.Context, server.InitPopulationProbe) {
	o.logger.Info().Msg("initial JWKS cache population started")
	return ctx, &loggingInitPopulationProbe{
		logger:    o.logger,
		startTime: o.clock.Now(),
		clock:     o.clock,
	}
}

func (o *LoggingJWKSObserver) CacheRefreshStarted(ctx context.Context) (context.Context, server.CacheRefreshProbe) {
	return ctx, &loggingCacheRefreshProbe{
		logger:    o.logger,
		startTime: o.clock.Now(),
		clock:     o.clock,
	}
}

type loggingInitPopulationProbe struct {
	server.NoOpInitPopulationProbe
	logger    zerolog.Logger
	startTime time.Time
	clock     clock.Clock
}

func (p *loggingInitPopulationProbe) InitialCachePopulationFailed(err error) {
	p.logger.Error().Err(err).Msg("initial JWKS cache population failed")
}

func (p *loggingInitPopulationProbe) End() {
	p.logger.Debug().
		Dur("duration", p.clock.Since(p.startTime)).
		Msg("initial JWKS cache population completed")
}

type loggingCacheRefreshProbe struct {
	server.NoOpCacheRefreshProbe
	logger    zerolog.Logger
	startTime time.Time
	clock     clock.Clock
}

func (p *loggingCacheRefreshProbe) CacheRefreshFailed(err error) {
	p.logger.Warn().Err(err).Msg("cache refresh failed")
}

func (p *loggingCacheRefreshProbe) KeyConversionFailed(keyID string, err error) {
	p.logger.Warn().Err(err).Str("key_id", keyID).Msg("skipping key: conversion failed")
}

func (p *loggingCacheRefreshProbe) End() {
	p.logger.Debug().
		Dur("duration", p.clock.Since(p.startTime)).
		Msg("cache refresh completed")
}
