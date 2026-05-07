package otel

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/project-kessel/parsec/internal/keys"
)

type keysObserver struct {
	keys.NoOpKeysObserver

	rotationTotal       metric.Int64Counter
	rotationDuration    metric.Float64Histogram
	cacheUpdateTotal    metric.Int64Counter
	cacheUpdateDuration metric.Float64Histogram

	kmsRotateTotal    metric.Int64Counter
	kmsRotateDuration metric.Float64Histogram

	diskRotateTotal    metric.Int64Counter
	diskRotateDuration metric.Float64Histogram

	memoryRotateTotal    metric.Int64Counter
	memoryRotateDuration metric.Float64Histogram
}

func newKeysObserver(m metric.Meter) (*keysObserver, error) {
	rt, err := m.Int64Counter("parsec.keys.rotation.total",
		metric.WithDescription("Total key rotation operations"),
	)
	if err != nil {
		return nil, err
	}
	rd, err := m.Float64Histogram("parsec.keys.rotation.duration",
		metric.WithDescription("Key rotation duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}
	cut, err := m.Int64Counter("parsec.keys.cache.update.total",
		metric.WithDescription("Total key cache update operations"),
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

	krt, err := m.Int64Counter("parsec.keys.kms.rotate.total",
		metric.WithDescription("Total KMS key rotation operations"),
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
	drt, err := m.Int64Counter("parsec.keys.disk.rotate.total",
		metric.WithDescription("Total disk key rotation operations"),
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
	mrt, err := m.Int64Counter("parsec.keys.memory.rotate.total",
		metric.WithDescription("Total in-memory key rotation operations"),
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
		rotationTotal:        rt,
		rotationDuration:     rd,
		cacheUpdateTotal:     cut,
		cacheUpdateDuration:  cud,
		kmsRotateTotal:       krt,
		kmsRotateDuration:    krd,
		diskRotateTotal:      drt,
		diskRotateDuration:   drd,
		memoryRotateTotal:    mrt,
		memoryRotateDuration: mrd,
	}, nil
}

func (o *keysObserver) RotationCheckStarted(ctx context.Context) (context.Context, keys.RotationCheckProbe) {
	return ctx, &rotationCheckProbe{metricProbe: metricProbe{
		ctx:       ctx,
		counter:   o.rotationTotal,
		histogram: o.rotationDuration,
		startTime: time.Now(),
	}}
}

type rotationCheckProbe struct {
	keys.NoOpRotationCheckProbe
	metricProbe
}

func (p *rotationCheckProbe) RotationCheckFailed(error) { p.markFailed() }
func (p *rotationCheckProbe) End()                      { p.record() }

// --- key cache update probe ---

func (o *keysObserver) KeyCacheUpdateStarted(ctx context.Context) (context.Context, keys.KeyCacheUpdateProbe) {
	return ctx, &keyCacheUpdateProbe{metricProbe: metricProbe{
		ctx:       ctx,
		counter:   o.cacheUpdateTotal,
		histogram: o.cacheUpdateDuration,
		startTime: time.Now(),
	}}
}

type keyCacheUpdateProbe struct {
	keys.NoOpKeyCacheUpdateProbe
	metricProbe
}

func (p *keyCacheUpdateProbe) KeyCacheUpdateFailed(error)         { p.markFailed() }
func (p *keyCacheUpdateProbe) KeyProviderNotFound(string, string) { p.markFailed() }
func (p *keyCacheUpdateProbe) KeyHandleFailed(string, error)      { p.markFailed() }
func (p *keyCacheUpdateProbe) PublicKeyFailed(string, error)      { p.markFailed() }
func (p *keyCacheUpdateProbe) ThumbprintFailed(string, error)     { p.markFailed() }
func (p *keyCacheUpdateProbe) MetadataFailed(string, error)       { p.markFailed() }
func (p *keyCacheUpdateProbe) End()                               { p.record() }

// --- KMS rotate probe ---

func (o *keysObserver) KMSRotateStarted(ctx context.Context, _, _, keyName string) (context.Context, keys.KMSRotateProbe) {
	return ctx, &kmsRotateProbe{
		metricProbe: metricProbe{
			ctx:       ctx,
			counter:   o.kmsRotateTotal,
			histogram: o.kmsRotateDuration,
			startTime: time.Now(),
		},
		keyName: keyName,
	}
}

// kmsRotateProbe records metrics for a single AWS KMS key rotation.
// The key_name attribute is bounded by the number of configured signing keys
// per deployment — not a per-request value.
type kmsRotateProbe struct {
	keys.NoOpKMSRotateProbe
	metricProbe
	keyName string
}

func (p *kmsRotateProbe) CreateKeyFailed(error)              { p.markFailed() }
func (p *kmsRotateProbe) AliasCheckFailed(error)             { p.markFailed() }
func (p *kmsRotateProbe) AliasUpdateFailed(error)            { p.markFailed() }
func (p *kmsRotateProbe) OldKeyDeletionFailed(string, error) { p.markFailed() }
func (p *kmsRotateProbe) End() {
	p.record(attribute.String("key_name", p.keyName))
}

// --- disk rotate probe ---

func (o *keysObserver) DiskRotateStarted(ctx context.Context, _, _, keyName string) (context.Context, keys.DiskRotateProbe) {
	return ctx, &diskRotateProbe{
		metricProbe: metricProbe{
			ctx:       ctx,
			counter:   o.diskRotateTotal,
			histogram: o.diskRotateDuration,
			startTime: time.Now(),
		},
		keyName: keyName,
	}
}

// diskRotateProbe records metrics for a single disk-based key rotation.
// The key_name attribute is bounded by the number of configured signing keys
// per deployment — not a per-request value.
type diskRotateProbe struct {
	keys.NoOpDiskRotateProbe
	metricProbe
	keyName string
}

func (p *diskRotateProbe) KeyGenerationFailed(error) { p.markFailed() }
func (p *diskRotateProbe) KeyWriteFailed(error)      { p.markFailed() }
func (p *diskRotateProbe) End() {
	p.record(attribute.String("key_name", p.keyName))
}

// --- memory rotate probe ---

func (o *keysObserver) MemoryRotateStarted(ctx context.Context) (context.Context, keys.MemoryRotateProbe) {
	return ctx, &memoryRotateProbe{metricProbe: metricProbe{
		ctx:       ctx,
		counter:   o.memoryRotateTotal,
		histogram: o.memoryRotateDuration,
		startTime: time.Now(),
	}}
}

type memoryRotateProbe struct {
	keys.NoOpMemoryRotateProbe
	metricProbe
}

func (p *memoryRotateProbe) KeyGenerationFailed(error) { p.markFailed() }
func (p *memoryRotateProbe) End()                      { p.record() }

var (
	_ keys.KeysObserver        = (*keysObserver)(nil)
	_ keys.RotationCheckProbe  = (*rotationCheckProbe)(nil)
	_ keys.KeyCacheUpdateProbe = (*keyCacheUpdateProbe)(nil)
	_ keys.KMSRotateProbe      = (*kmsRotateProbe)(nil)
	_ keys.DiskRotateProbe     = (*diskRotateProbe)(nil)
	_ keys.MemoryRotateProbe   = (*memoryRotateProbe)(nil)
)
