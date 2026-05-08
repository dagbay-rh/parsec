package otel

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/project-kessel/parsec/internal/keys"
)

var (
	rotationResultCompleted = attribute.String("result", "completed")
	rotationResultSkipped   = attribute.String("result", "skipped_version_race")
	rotationResultNotNeeded = attribute.String("result", "not_needed")
	rotationResultFailed    = attribute.String("result", "failed")

	cacheUpdateResultGeneralFailure   = attribute.String("result", "general_failure")
	cacheUpdateResultProviderNotFound = attribute.String("result", "provider_not_found")
	cacheUpdateResultKeyHandleFailed  = attribute.String("result", "key_handle_failed")
	cacheUpdateResultPublicKeyFailed  = attribute.String("result", "public_key_failed")
	cacheUpdateResultThumbprintFailed = attribute.String("result", "thumbprint_failed")
	cacheUpdateResultMetadataFailed   = attribute.String("result", "metadata_failed")
)

type keysObserver struct {
	keys.NoOpKeysObserver

	rotationDuration     metric.Float64Histogram
	cacheUpdateDuration  metric.Float64Histogram
	kmsRotateDuration    metric.Float64Histogram
	diskRotateDuration   metric.Float64Histogram
	memoryRotateDuration metric.Float64Histogram
}

func newKeysObserver(m metric.Meter) (*keysObserver, error) {
	rd, err := m.Float64Histogram("parsec.keys.rotation.duration",
		metric.WithDescription("Key rotation check duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}
	cud, err := m.Float64Histogram("parsec.keys.cache.update.duration",
		metric.WithDescription("Key cache update duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}
	krd, err := m.Float64Histogram("parsec.keys.kms.rotate.duration",
		metric.WithDescription("KMS key rotation duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}
	drd, err := m.Float64Histogram("parsec.keys.disk.rotate.duration",
		metric.WithDescription("Disk key rotation duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}
	mrd, err := m.Float64Histogram("parsec.keys.memory.rotate.duration",
		metric.WithDescription("In-memory key rotation duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	return &keysObserver{
		rotationDuration:     rd,
		cacheUpdateDuration:  cud,
		kmsRotateDuration:    krd,
		diskRotateDuration:   drd,
		memoryRotateDuration: mrd,
	}, nil
}

// --- rotation check probe ---

func (o *keysObserver) RotationCheckStarted(ctx context.Context) (context.Context, keys.RotationCheckProbe) {
	return ctx, &rotationCheckProbe{
		obs: o, ctx: ctx, startTime: time.Now(),
		status: successStatusAttr,
	}
}

type rotationCheckProbe struct {
	keys.NoOpRotationCheckProbe
	obs       *keysObserver
	ctx       context.Context
	startTime time.Time
	status    attribute.KeyValue
	result    attribute.KeyValue
}

func (p *rotationCheckProbe) RotationCheckFailed(_ error) {
	p.status = errorStatusAttr
	p.result = rotationResultFailed
}
func (p *rotationCheckProbe) RotationCompleted(_ string)          { p.result = rotationResultCompleted }
func (p *rotationCheckProbe) RotationSkippedVersionRace(_ string) { p.result = rotationResultSkipped }
func (p *rotationCheckProbe) End() {
	if p.result == (attribute.KeyValue{}) {
		p.result = rotationResultNotNeeded
	}
	attrs := metric.WithAttributeSet(attribute.NewSet(p.result, p.status))
	p.obs.rotationDuration.Record(p.ctx, time.Since(p.startTime).Seconds(), attrs)
}

// --- key cache update probe ---

func (o *keysObserver) KeyCacheUpdateStarted(ctx context.Context) (context.Context, keys.KeyCacheUpdateProbe) {
	return ctx, &keyCacheUpdateProbe{
		obs: o, ctx: ctx, startTime: time.Now(),
		status: successStatusAttr, result: resultSuccess,
	}
}

type keyCacheUpdateProbe struct {
	keys.NoOpKeyCacheUpdateProbe
	obs       *keysObserver
	ctx       context.Context
	startTime time.Time
	status    attribute.KeyValue
	result    attribute.KeyValue
}

func (p *keyCacheUpdateProbe) KeyCacheUpdateFailed(_ error) {
	p.status = errorStatusAttr
	p.result = cacheUpdateResultGeneralFailure
}
func (p *keyCacheUpdateProbe) KeyProviderNotFound(_ string, _ string) {
	p.status = errorStatusAttr
	p.result = cacheUpdateResultProviderNotFound
}
func (p *keyCacheUpdateProbe) KeyHandleFailed(_ string, _ error) {
	p.status = errorStatusAttr
	p.result = cacheUpdateResultKeyHandleFailed
}
func (p *keyCacheUpdateProbe) PublicKeyFailed(_ string, _ error) {
	p.status = errorStatusAttr
	p.result = cacheUpdateResultPublicKeyFailed
}
func (p *keyCacheUpdateProbe) ThumbprintFailed(_ string, _ error) {
	p.status = errorStatusAttr
	p.result = cacheUpdateResultThumbprintFailed
}
func (p *keyCacheUpdateProbe) MetadataFailed(_ string, _ error) {
	p.status = errorStatusAttr
	p.result = cacheUpdateResultMetadataFailed
}
func (p *keyCacheUpdateProbe) End() {
	attrs := metric.WithAttributeSet(attribute.NewSet(p.result, p.status))
	p.obs.cacheUpdateDuration.Record(p.ctx, time.Since(p.startTime).Seconds(), attrs)
}

// --- KMS rotate probe ---

func (o *keysObserver) KMSRotateStarted(ctx context.Context, _, _, keyName string) (context.Context, keys.KMSRotateProbe) {
	return ctx, &kmsRotateProbe{
		obs: o, ctx: ctx, startTime: time.Now(),
		status:  successStatusAttr,
		keyName: attribute.String("key_name", keyName),
	}
}

// kmsRotateProbe records metrics for a single AWS KMS key rotation.
// The key_name attribute is bounded by the number of configured signing keys
// per deployment — not a per-request value.
type kmsRotateProbe struct {
	keys.NoOpKMSRotateProbe
	obs       *keysObserver
	ctx       context.Context
	startTime time.Time
	status    attribute.KeyValue
	keyName   attribute.KeyValue
}

func (p *kmsRotateProbe) CreateKeyFailed(_ error)                { p.status = errorStatusAttr }
func (p *kmsRotateProbe) AliasCheckFailed(_ error)               { p.status = errorStatusAttr }
func (p *kmsRotateProbe) AliasUpdateFailed(_ error)              { p.status = errorStatusAttr }
func (p *kmsRotateProbe) OldKeyDeletionFailed(_ string, _ error) { p.status = errorStatusAttr }
func (p *kmsRotateProbe) End() {
	attrs := metric.WithAttributeSet(attribute.NewSet(p.keyName, p.status))
	p.obs.kmsRotateDuration.Record(p.ctx, time.Since(p.startTime).Seconds(), attrs)
}

// --- disk rotate probe ---

func (o *keysObserver) DiskRotateStarted(ctx context.Context, _, _, keyName string) (context.Context, keys.DiskRotateProbe) {
	return ctx, &diskRotateProbe{
		obs: o, ctx: ctx, startTime: time.Now(),
		status:  successStatusAttr,
		keyName: attribute.String("key_name", keyName),
	}
}

// diskRotateProbe records metrics for a single disk-based key rotation.
// The key_name attribute is bounded by the number of configured signing keys
// per deployment — not a per-request value.
type diskRotateProbe struct {
	keys.NoOpDiskRotateProbe
	obs       *keysObserver
	ctx       context.Context
	startTime time.Time
	status    attribute.KeyValue
	keyName   attribute.KeyValue
}

func (p *diskRotateProbe) KeyGenerationFailed(_ error) { p.status = errorStatusAttr }
func (p *diskRotateProbe) KeyWriteFailed(_ error)      { p.status = errorStatusAttr }
func (p *diskRotateProbe) End() {
	attrs := metric.WithAttributeSet(attribute.NewSet(p.keyName, p.status))
	p.obs.diskRotateDuration.Record(p.ctx, time.Since(p.startTime).Seconds(), attrs)
}

// --- memory rotate probe ---

func (o *keysObserver) MemoryRotateStarted(ctx context.Context) (context.Context, keys.MemoryRotateProbe) {
	return ctx, &memoryRotateProbe{
		obs: o, ctx: ctx, startTime: time.Now(),
		status: successStatusAttr,
	}
}

type memoryRotateProbe struct {
	keys.NoOpMemoryRotateProbe
	obs       *keysObserver
	ctx       context.Context
	startTime time.Time
	status    attribute.KeyValue
}

func (p *memoryRotateProbe) KeyGenerationFailed(_ error) { p.status = errorStatusAttr }
func (p *memoryRotateProbe) End() {
	attrs := metric.WithAttributeSet(attribute.NewSet(p.status))
	p.obs.memoryRotateDuration.Record(p.ctx, time.Since(p.startTime).Seconds(), attrs)
}

var (
	_ keys.KeysObserver        = (*keysObserver)(nil)
	_ keys.RotationCheckProbe  = (*rotationCheckProbe)(nil)
	_ keys.KeyCacheUpdateProbe = (*keyCacheUpdateProbe)(nil)
	_ keys.KMSRotateProbe      = (*kmsRotateProbe)(nil)
	_ keys.DiskRotateProbe     = (*diskRotateProbe)(nil)
	_ keys.MemoryRotateProbe   = (*memoryRotateProbe)(nil)
)
