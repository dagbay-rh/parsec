package zlog

import (
	"context"
	"time"

	"github.com/rs/zerolog"

	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/keys"
)

var (
	_ keys.DualSlotRotatingSignerObserver = (*LoggingKeyRotationObserver)(nil)
	_ keys.AWSKMSProviderObserver         = (*LoggingAWSKMSProviderObserver)(nil)
	_ keys.DiskProviderObserver           = (*LoggingDiskProviderObserver)(nil)
	_ keys.InMemoryProviderObserver       = (*LoggingInMemoryProviderObserver)(nil)
)

// LoggingKeyRotationObserver logs key rotation lifecycle events via zerolog.
type LoggingKeyRotationObserver struct {
	keys.NoOpDualSlotRotatingSignerObserver
	logger zerolog.Logger
	clock  clock.Clock
}

func NewLoggingKeyRotationObserver(logger zerolog.Logger, opts ...Option) *LoggingKeyRotationObserver {
	cfg := resolveOptions(opts)
	return &LoggingKeyRotationObserver{logger: logger, clock: cfg.clk}
}

func (o *LoggingKeyRotationObserver) RotationCheckStarted(ctx context.Context) (context.Context, keys.RotationCheckProbe) {
	return ctx, &loggingRotationCheckProbe{
		logger:    o.logger,
		startTime: o.clock.Now(),
		clock:     o.clock,
	}
}

func (o *LoggingKeyRotationObserver) KeyCacheUpdateStarted(ctx context.Context) (context.Context, keys.KeyCacheUpdateProbe) {
	return ctx, &loggingKeyCacheUpdateProbe{
		logger:    o.logger,
		startTime: o.clock.Now(),
		clock:     o.clock,
	}
}

type loggingRotationCheckProbe struct {
	keys.NoOpRotationCheckProbe
	logger    zerolog.Logger
	startTime time.Time
	clock     clock.Clock
}

func (p *loggingRotationCheckProbe) RotationCheckFailed(err error) {
	p.logger.Error().Err(err).Msg("key rotation check failed")
}

func (p *loggingRotationCheckProbe) RotationCompleted(slot string) {
	p.logger.Info().Str("slot", slot).Msg("key rotation completed")
}

func (p *loggingRotationCheckProbe) RotationSkippedVersionRace(slot string) {
	p.logger.Info().Str("slot", slot).Msg("another process completed rotation, skipping")
}

func (p *loggingRotationCheckProbe) End() {
	p.logger.Debug().
		Dur("duration", p.clock.Since(p.startTime)).
		Msg("rotation check completed")
}

type loggingKeyCacheUpdateProbe struct {
	keys.NoOpKeyCacheUpdateProbe
	logger    zerolog.Logger
	startTime time.Time
	clock     clock.Clock
}

func (p *loggingKeyCacheUpdateProbe) KeyCacheUpdateFailed(err error) {
	p.logger.Error().Err(err).Msg("active key cache update failed")
}

func (p *loggingKeyCacheUpdateProbe) KeyProviderNotFound(provider, slot string) {
	p.logger.Warn().Str("provider", provider).Str("slot", slot).Msg("key provider not found, skipping")
}

func (p *loggingKeyCacheUpdateProbe) KeyHandleFailed(slot string, err error) {
	p.logger.Warn().Err(err).Str("slot", slot).Msg("failed to get key handle")
}

func (p *loggingKeyCacheUpdateProbe) PublicKeyFailed(slot string, err error) {
	p.logger.Warn().Err(err).Str("slot", slot).Msg("failed to get public key")
}

func (p *loggingKeyCacheUpdateProbe) ThumbprintFailed(slot string, err error) {
	p.logger.Warn().Err(err).Str("slot", slot).Msg("failed to compute thumbprint")
}

func (p *loggingKeyCacheUpdateProbe) MetadataFailed(slot string, err error) {
	p.logger.Warn().Err(err).Str("slot", slot).Msg("failed to get key metadata")
}

func (p *loggingKeyCacheUpdateProbe) End() {
	p.logger.Debug().
		Dur("duration", p.clock.Since(p.startTime)).
		Msg("key cache update completed")
}

// --- AWS KMS ---

type LoggingAWSKMSProviderObserver struct {
	keys.NoOpAWSKMSProviderObserver
	logger zerolog.Logger
	clock  clock.Clock
}

func NewLoggingAWSKMSProviderObserver(logger zerolog.Logger, opts ...Option) *LoggingAWSKMSProviderObserver {
	cfg := resolveOptions(opts)
	return &LoggingAWSKMSProviderObserver{logger: logger, clock: cfg.clk}
}

func (o *LoggingAWSKMSProviderObserver) KMSRotateStarted(ctx context.Context, trustDomain, namespace, keyName string) (context.Context, keys.KMSRotateProbe) {
	o.logger.Info().
		Str("trust_domain", trustDomain).
		Str("namespace", namespace).
		Str("key_name", keyName).
		Msg("KMS key rotation started")
	return ctx, &loggingKMSRotateProbe{
		logger:    o.logger,
		startTime: o.clock.Now(),
		clock:     o.clock,
	}
}

type loggingKMSRotateProbe struct {
	keys.NoOpKMSRotateProbe
	logger    zerolog.Logger
	startTime time.Time
	clock     clock.Clock
}

func (p *loggingKMSRotateProbe) CreateKeyFailed(err error) {
	p.logger.Error().Err(err).Msg("KMS CreateKey failed")
}

func (p *loggingKMSRotateProbe) AliasCheckFailed(err error) {
	p.logger.Error().Err(err).Msg("KMS alias check failed")
}

func (p *loggingKMSRotateProbe) AliasUpdateFailed(err error) {
	p.logger.Error().Err(err).Msg("KMS alias update failed")
}

func (p *loggingKMSRotateProbe) OldKeyDeletionFailed(keyID string, err error) {
	p.logger.Warn().Err(err).Str("key_id", keyID).Msg("failed to schedule old KMS key for deletion")
}

func (p *loggingKMSRotateProbe) End() {
	p.logger.Debug().
		Dur("duration", p.clock.Since(p.startTime)).
		Msg("KMS key rotation completed")
}

// --- Disk ---

type LoggingDiskProviderObserver struct {
	keys.NoOpDiskProviderObserver
	logger zerolog.Logger
	clock  clock.Clock
}

func NewLoggingDiskProviderObserver(logger zerolog.Logger, opts ...Option) *LoggingDiskProviderObserver {
	cfg := resolveOptions(opts)
	return &LoggingDiskProviderObserver{logger: logger, clock: cfg.clk}
}

func (o *LoggingDiskProviderObserver) DiskRotateStarted(ctx context.Context, trustDomain, namespace, keyName string) (context.Context, keys.DiskRotateProbe) {
	o.logger.Info().
		Str("trust_domain", trustDomain).
		Str("namespace", namespace).
		Str("key_name", keyName).
		Msg("disk key rotation started")
	return ctx, &loggingDiskRotateProbe{
		logger:    o.logger,
		startTime: o.clock.Now(),
		clock:     o.clock,
	}
}

type loggingDiskRotateProbe struct {
	keys.NoOpDiskRotateProbe
	logger    zerolog.Logger
	startTime time.Time
	clock     clock.Clock
}

func (p *loggingDiskRotateProbe) KeyGenerationFailed(err error) {
	p.logger.Error().Err(err).Msg("disk key generation failed")
}

func (p *loggingDiskRotateProbe) KeyWriteFailed(err error) {
	p.logger.Error().Err(err).Msg("disk key write failed")
}

func (p *loggingDiskRotateProbe) End() {
	p.logger.Debug().
		Dur("duration", p.clock.Since(p.startTime)).
		Msg("disk key rotation completed")
}

// --- In-Memory ---

type LoggingInMemoryProviderObserver struct {
	keys.NoOpInMemoryProviderObserver
	logger zerolog.Logger
	clock  clock.Clock
}

func NewLoggingInMemoryProviderObserver(logger zerolog.Logger, opts ...Option) *LoggingInMemoryProviderObserver {
	cfg := resolveOptions(opts)
	return &LoggingInMemoryProviderObserver{logger: logger, clock: cfg.clk}
}

func (o *LoggingInMemoryProviderObserver) MemoryRotateStarted(ctx context.Context) (context.Context, keys.MemoryRotateProbe) {
	o.logger.Info().Msg("in-memory key rotation started")
	return ctx, &loggingMemoryRotateProbe{
		logger:    o.logger,
		startTime: o.clock.Now(),
		clock:     o.clock,
	}
}

type loggingMemoryRotateProbe struct {
	keys.NoOpMemoryRotateProbe
	logger    zerolog.Logger
	startTime time.Time
	clock     clock.Clock
}

func (p *loggingMemoryRotateProbe) KeyGenerationFailed(err error) {
	p.logger.Error().Err(err).Msg("in-memory key generation failed")
}

func (p *loggingMemoryRotateProbe) End() {
	p.logger.Debug().
		Dur("duration", p.clock.Since(p.startTime)).
		Msg("in-memory key rotation completed")
}
