package zlog

import (
	"context"

	"github.com/rs/zerolog"

	"github.com/project-kessel/parsec/internal/datasource"
	"github.com/project-kessel/parsec/internal/keys"
	"github.com/project-kessel/parsec/internal/server"
)

// LoggingDataSourceObserver satisfies datasource.DataSourceObserver
// by combining cache and Lua logging observers.
type LoggingDataSourceObserver struct {
	datasource.NoOpDataSourceObserver
	cache *LoggingDataSourceCacheObserver
	lua   *LoggingLuaDataSourceObserver
}

func NewLoggingDataSourceObserver(cacheLogger, luaLogger zerolog.Logger) *LoggingDataSourceObserver {
	return &LoggingDataSourceObserver{
		cache: NewLoggingDataSourceCacheObserver(cacheLogger),
		lua:   NewLoggingLuaDataSourceObserver(luaLogger),
	}
}

func (o *LoggingDataSourceObserver) CacheFetchStarted(ctx context.Context, dataSourceName string) (context.Context, datasource.CacheFetchProbe) {
	return o.cache.CacheFetchStarted(ctx, dataSourceName)
}

func (o *LoggingDataSourceObserver) LuaFetchStarted(ctx context.Context, dataSourceName string) (context.Context, datasource.LuaFetchProbe) {
	return o.lua.LuaFetchStarted(ctx, dataSourceName)
}

var _ datasource.DataSourceObserver = (*LoggingDataSourceObserver)(nil)

// LoggingKeysObserver satisfies keys.KeysObserver
// by combining rotation and per-provider logging observers.
type LoggingKeysObserver struct {
	keys.NoOpKeysObserver
	rotation *LoggingKeyRotationObserver
	kms      *LoggingAWSKMSProviderObserver
	disk     *LoggingDiskProviderObserver
	memory   *LoggingInMemoryProviderObserver
}

func NewLoggingKeysObserver(rotationLogger, providerLogger zerolog.Logger) *LoggingKeysObserver {
	return &LoggingKeysObserver{
		rotation: NewLoggingKeyRotationObserver(rotationLogger),
		kms:      NewLoggingAWSKMSProviderObserver(providerLogger),
		disk:     NewLoggingDiskProviderObserver(providerLogger),
		memory:   NewLoggingInMemoryProviderObserver(providerLogger),
	}
}

func (o *LoggingKeysObserver) RotationCheckStarted(ctx context.Context) (context.Context, keys.RotationCheckProbe) {
	return o.rotation.RotationCheckStarted(ctx)
}

func (o *LoggingKeysObserver) KeyCacheUpdateStarted(ctx context.Context) (context.Context, keys.KeyCacheUpdateProbe) {
	return o.rotation.KeyCacheUpdateStarted(ctx)
}

func (o *LoggingKeysObserver) KMSRotateStarted(ctx context.Context, trustDomain, namespace, keyName string) (context.Context, keys.KMSRotateProbe) {
	return o.kms.KMSRotateStarted(ctx, trustDomain, namespace, keyName)
}

func (o *LoggingKeysObserver) DiskRotateStarted(ctx context.Context, trustDomain, namespace, keyName string) (context.Context, keys.DiskRotateProbe) {
	return o.disk.DiskRotateStarted(ctx, trustDomain, namespace, keyName)
}

func (o *LoggingKeysObserver) MemoryRotateStarted(ctx context.Context) (context.Context, keys.MemoryRotateProbe) {
	return o.memory.MemoryRotateStarted(ctx)
}

var _ keys.KeysObserver = (*LoggingKeysObserver)(nil)

// LoggingServerObserver satisfies server.ServerObserver
// by combining JWKS and lifecycle logging observers.
type LoggingServerObserver struct {
	server.NoOpServerObserver
	jwks      *LoggingJWKSObserver
	lifecycle *LoggingServerLifecycleObserver
}

func NewLoggingServerObserver(jwksLogger, lifecycleLogger zerolog.Logger) *LoggingServerObserver {
	return &LoggingServerObserver{
		jwks:      NewLoggingJWKSObserver(jwksLogger),
		lifecycle: NewLoggingServerLifecycleObserver(lifecycleLogger),
	}
}

func (o *LoggingServerObserver) InitPopulationStarted(ctx context.Context) (context.Context, server.InitPopulationProbe) {
	return o.jwks.InitPopulationStarted(ctx)
}

func (o *LoggingServerObserver) CacheRefreshStarted(ctx context.Context) (context.Context, server.CacheRefreshProbe) {
	return o.jwks.CacheRefreshStarted(ctx)
}

func (o *LoggingServerObserver) GRPCServeFailed(err error) {
	o.lifecycle.GRPCServeFailed(err)
}

func (o *LoggingServerObserver) HTTPServeFailed(err error) {
	o.lifecycle.HTTPServeFailed(err)
}

func (o *LoggingServerObserver) StopStarted(ctx context.Context) (context.Context, server.StopProbe) {
	return o.lifecycle.StopStarted(ctx)
}

var _ server.ServerObserver = (*LoggingServerObserver)(nil)
