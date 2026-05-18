package zlog

import (
	"context"
	"time"

	"github.com/rs/zerolog"

	"github.com/project-kessel/parsec/internal/server"
)

var _ server.JWKSObserver = (*LoggingJWKSObserver)(nil)

// LoggingJWKSObserver logs JWKS cache lifecycle events via zerolog.
type LoggingJWKSObserver struct {
	server.NoOpJWKSObserver
	logger zerolog.Logger
}

func NewLoggingJWKSObserver(logger zerolog.Logger) *LoggingJWKSObserver {
	return &LoggingJWKSObserver{logger: logger}
}

func (o *LoggingJWKSObserver) InitPopulationStarted(ctx context.Context) (context.Context, server.InitPopulationProbe) {
	o.logger.Info().Msg("initial JWKS cache population started")
	return ctx, &loggingInitPopulationProbe{
		logger:    o.logger,
		startTime: time.Now(),
	}
}

func (o *LoggingJWKSObserver) CacheRefreshStarted(ctx context.Context) (context.Context, server.CacheRefreshProbe) {
	return ctx, &loggingCacheRefreshProbe{
		logger:    o.logger,
		startTime: time.Now(),
	}
}

type loggingInitPopulationProbe struct {
	server.NoOpInitPopulationProbe
	logger    zerolog.Logger
	startTime time.Time
}

func (p *loggingInitPopulationProbe) InitialCachePopulationFailed(err error) {
	p.logger.Error().Err(err).Msg("initial JWKS cache population failed")
}

func (p *loggingInitPopulationProbe) End() {
	p.logger.Debug().
		Dur("duration", time.Since(p.startTime)).
		Msg("initial JWKS cache population completed")
}

type loggingCacheRefreshProbe struct {
	server.NoOpCacheRefreshProbe
	logger    zerolog.Logger
	startTime time.Time
}

func (p *loggingCacheRefreshProbe) CacheRefreshFailed(err error) {
	p.logger.Warn().Err(err).Msg("cache refresh failed")
}

func (p *loggingCacheRefreshProbe) KeyConversionFailed(keyID string, err error) {
	p.logger.Warn().Err(err).Str("key_id", keyID).Msg("skipping key: conversion failed")
}

func (p *loggingCacheRefreshProbe) End() {
	p.logger.Debug().
		Dur("duration", time.Since(p.startTime)).
		Msg("cache refresh completed")
}
