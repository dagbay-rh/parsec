package zlog

import (
	"context"
	"time"

	"github.com/rs/zerolog"

	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/datasource"
)

var _ datasource.CacheObserver = (*LoggingDataSourceCacheObserver)(nil)

// LoggingDataSourceCacheObserver logs data source cache events via zerolog.
type LoggingDataSourceCacheObserver struct {
	datasource.NoOpCacheObserver
	logger zerolog.Logger
	clock  clock.Clock
}

func NewLoggingDataSourceCacheObserver(logger zerolog.Logger, opts ...Option) *LoggingDataSourceCacheObserver {
	cfg := resolveOptions(opts)
	return &LoggingDataSourceCacheObserver{logger: logger, clock: cfg.clk}
}

func (o *LoggingDataSourceCacheObserver) CacheFetchStarted(ctx context.Context, dataSourceName string) (context.Context, datasource.CacheFetchProbe) {
	return ctx, &loggingCacheFetchProbe{
		logger:    o.logger.With().Str("datasource", dataSourceName).Logger(),
		startTime: o.clock.Now(),
		clock:     o.clock,
	}
}

type loggingCacheFetchProbe struct {
	datasource.NoOpCacheFetchProbe
	logger    zerolog.Logger
	startTime time.Time
	clock     clock.Clock
}

func (p *loggingCacheFetchProbe) CacheHit() {
	p.logger.Debug().Msg("cache hit")
}

func (p *loggingCacheFetchProbe) CacheMiss() {
	p.logger.Debug().Msg("cache miss")
}

func (p *loggingCacheFetchProbe) CacheExpired() {
	p.logger.Debug().Msg("cache entry expired")
}

func (p *loggingCacheFetchProbe) FetchFailed(err error) {
	p.logger.Warn().Err(err).Msg("data source fetch failed")
}

func (p *loggingCacheFetchProbe) End() {
	p.logger.Debug().
		Dur("duration", p.clock.Since(p.startTime)).
		Msg("cache fetch completed")
}
