package zlog

import (
	"context"
	"time"

	"github.com/rs/zerolog"

	"github.com/project-kessel/parsec/internal/datasource"
)

var _ datasource.CacheObserver = (*LoggingDataSourceCacheObserver)(nil)

// LoggingDataSourceCacheObserver logs data source cache events via zerolog.
type LoggingDataSourceCacheObserver struct {
	datasource.NoOpCacheObserver
	logger zerolog.Logger
}

func NewLoggingDataSourceCacheObserver(logger zerolog.Logger) *LoggingDataSourceCacheObserver {
	return &LoggingDataSourceCacheObserver{logger: logger}
}

func (o *LoggingDataSourceCacheObserver) CacheFetchStarted(ctx context.Context, dataSourceName string) (context.Context, datasource.CacheFetchProbe) {
	return ctx, &loggingCacheFetchProbe{
		logger:    o.logger.With().Str("datasource", dataSourceName).Logger(),
		startTime: time.Now(),
	}
}

type loggingCacheFetchProbe struct {
	datasource.NoOpCacheFetchProbe
	logger    zerolog.Logger
	startTime time.Time
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
		Dur("duration", time.Since(p.startTime)).
		Msg("cache fetch completed")
}
