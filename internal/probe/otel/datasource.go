package otel

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/project-kessel/parsec/internal/datasource"
)

type dataSourceObserver struct {
	datasource.NoOpDataSourceObserver

	cacheFetchTotal    metric.Int64Counter
	cacheFetchDuration metric.Float64Histogram
	luaFetchTotal      metric.Int64Counter
	luaFetchDuration   metric.Float64Histogram
}

func newDataSourceObserver(m metric.Meter) (*dataSourceObserver, error) {
	cft, err := m.Int64Counter("parsec.datasource.cache.fetch.total",
		metric.WithDescription("Total data source cache fetch operations"),
	)
	if err != nil {
		return nil, err
	}
	cfd, err := m.Float64Histogram("parsec.datasource.cache.fetch.duration",
		metric.WithDescription("Data source cache fetch duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}
	lft, err := m.Int64Counter("parsec.datasource.lua.fetch.total",
		metric.WithDescription("Total Lua data source fetch operations"),
	)
	if err != nil {
		return nil, err
	}
	lfd, err := m.Float64Histogram("parsec.datasource.lua.fetch.duration",
		metric.WithDescription("Lua data source fetch duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	return &dataSourceObserver{
		cacheFetchTotal:    cft,
		cacheFetchDuration: cfd,
		luaFetchTotal:      lft,
		luaFetchDuration:   lfd,
	}, nil
}

func (o *dataSourceObserver) CacheFetchStarted(ctx context.Context, dataSourceName string) (context.Context, datasource.CacheFetchProbe) {
	return ctx, &cacheFetchProbe{
		metricProbe: metricProbe{
			ctx:       ctx,
			counter:   o.cacheFetchTotal,
			histogram: o.cacheFetchDuration,
			startTime: time.Now(),
		},
		dataSourceName: dataSourceName,
	}
}

func (o *dataSourceObserver) LuaFetchStarted(ctx context.Context, dataSourceName string) (context.Context, datasource.LuaFetchProbe) {
	return ctx, &luaFetchProbe{
		metricProbe: metricProbe{
			ctx:       ctx,
			counter:   o.luaFetchTotal,
			histogram: o.luaFetchDuration,
			startTime: time.Now(),
		},
		successAttrs: metric.WithAttributeSet(attribute.NewSet(successStatusAttr, attribute.String("datasource", dataSourceName))),
		errorAttrs:   metric.WithAttributeSet(attribute.NewSet(errorStatusAttr, attribute.String("datasource", dataSourceName))),
	}
}

type cacheFetchProbe struct {
	datasource.NoOpCacheFetchProbe
	metricProbe
	dataSourceName string
	result         string
}

func (p *cacheFetchProbe) CacheHit()     { p.result = "hit" }
func (p *cacheFetchProbe) CacheMiss()    { p.result = "miss" }
func (p *cacheFetchProbe) CacheExpired() { p.result = "expired" }
func (p *cacheFetchProbe) FetchFailed(error) {
	p.result = "error"
	p.markFailed()
}

func (p *cacheFetchProbe) End() {
	if p.result == "" {
		p.result = "unknown"
	}
	p.record(metric.WithAttributeSet(attribute.NewSet(
		p.statusAttr(),
		attribute.String("datasource", p.dataSourceName),
		attribute.String("result", p.result),
	)))
}

type luaFetchProbe struct {
	datasource.NoOpLuaFetchProbe
	metricProbe
	successAttrs metric.MeasurementOption
	errorAttrs   metric.MeasurementOption
}

func (p *luaFetchProbe) ScriptLoadFailed(error)       { p.markFailed() }
func (p *luaFetchProbe) ScriptExecutionFailed(error)  { p.markFailed() }
func (p *luaFetchProbe) InvalidReturnType(string)     { p.markFailed() }
func (p *luaFetchProbe) ResultConversionFailed(error) { p.markFailed() }

func (p *luaFetchProbe) End() {
	if p.failed {
		p.record(p.errorAttrs)
	} else {
		p.record(p.successAttrs)
	}
}

var (
	_ datasource.DataSourceObserver = (*dataSourceObserver)(nil)
	_ datasource.CacheFetchProbe    = (*cacheFetchProbe)(nil)
	_ datasource.LuaFetchProbe      = (*luaFetchProbe)(nil)
)
