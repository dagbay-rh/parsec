package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/golang/groupcache"

	"github.com/project-kessel/parsec/internal/clock"
)

// GroupcacheAdapter wraps a groupcache group with typed key/value
// serialization and TTL-bucketed cache keys.
//
// K is the domain key type (e.g. ValidatorInput, *DataSourceInput).
// V is the domain value type (e.g. *Result, *cachedEntry).
type GroupcacheAdapter[K any, V any] struct {
	group            *groupcache.Group
	clock            clock.Clock
	ttl              func() TTL
	serializeKey     func(K) (string, error)
	deserializeKey   func(string) (K, error)
	fetch            func(context.Context, K) (V, error)
	serializeValue   func(V) ([]byte, error)
	deserializeValue func([]byte) (V, error)
}

// TTL is the time-to-live for a cache entry.
type TTL = time.Duration

// GroupcacheAdapterConfig configures a [GroupcacheAdapter].
type GroupcacheAdapterConfig[K any, V any] struct {
	// GroupName identifies this groupcache group. Must be unique per process.
	GroupName string

	// CacheSizeBytes is the maximum size of the cache in bytes.
	// Default: 64 MB.
	CacheSizeBytes int64

	// Clock provides the current time. Required for TTL bucketing.
	Clock clock.Clock

	// TTL returns the time-to-live for cached entries.
	// Called on each Get to allow dynamic TTL (though typically static).
	TTL func() TTL

	// SerializeKey converts a domain key into a reversible string
	// representation suitable for use as a groupcache key.
	SerializeKey func(K) (string, error)

	// DeserializeKey reconstructs a domain key from its serialized form.
	// Called inside the groupcache getter, potentially on a remote peer.
	DeserializeKey func(string) (K, error)

	// Fetch retrieves the value from the underlying source on a cache miss.
	// Returning an error prevents the result from being cached.
	Fetch func(context.Context, K) (V, error)

	// SerializeValue encodes a value for storage in groupcache.
	SerializeValue func(V) ([]byte, error)

	// DeserializeValue decodes a value retrieved from groupcache.
	DeserializeValue func([]byte) (V, error)
}

// NewGroupcacheAdapter creates a [GroupcacheAdapter] from the given config.
// Returns an error if required config fields are missing.
func NewGroupcacheAdapter[K any, V any](config GroupcacheAdapterConfig[K, V]) (*GroupcacheAdapter[K, V], error) {
	if config.Clock == nil {
		config.Clock = clock.NewSystemClock()
	}
	if config.CacheSizeBytes == 0 {
		config.CacheSizeBytes = 64 << 20
	}
	if config.GroupName == "" {
		return nil, fmt.Errorf("cache: GroupName is required")
	}
	if config.SerializeKey == nil {
		return nil, fmt.Errorf("cache: SerializeKey is required")
	}
	if config.DeserializeKey == nil {
		return nil, fmt.Errorf("cache: DeserializeKey is required")
	}
	if config.Fetch == nil {
		return nil, fmt.Errorf("cache: Fetch is required")
	}
	if config.SerializeValue == nil {
		return nil, fmt.Errorf("cache: SerializeValue is required")
	}
	if config.DeserializeValue == nil {
		return nil, fmt.Errorf("cache: DeserializeValue is required")
	}

	a := &GroupcacheAdapter[K, V]{
		clock:            config.Clock,
		ttl:              config.TTL,
		serializeKey:     config.SerializeKey,
		deserializeKey:   config.DeserializeKey,
		fetch:            config.Fetch,
		serializeValue:   config.SerializeValue,
		deserializeValue: config.DeserializeValue,
	}

	getter := groupcache.GetterFunc(func(ctx context.Context, key string, dest groupcache.Sink) error {
		stripped := StripTTLSuffix(key)

		domainKey, err := a.deserializeKey(stripped)
		if err != nil {
			return fmt.Errorf("cache: failed to deserialize key: %w", err)
		}

		value, err := a.fetch(ctx, domainKey)
		if err != nil {
			return fmt.Errorf("cache: fetch failed: %w", err)
		}

		encoded, err := a.serializeValue(value)
		if err != nil {
			return fmt.Errorf("cache: failed to serialize value: %w", err)
		}

		return dest.SetBytes(encoded)
	})

	a.group = groupcache.NewGroup(config.GroupName, config.CacheSizeBytes, getter)
	return a, nil
}

// Get retrieves a value from the cache, fetching from the source on a miss.
// The key is serialized, TTL-bucketed, and passed to groupcache.
func (a *GroupcacheAdapter[K, V]) Get(ctx context.Context, key K) (V, error) {
	var zero V

	keyStr, err := a.serializeKey(key)
	if err != nil {
		return zero, fmt.Errorf("cache: failed to serialize key: %w", err)
	}

	var ttl TTL
	if a.ttl != nil {
		ttl = a.ttl()
	}
	keyStr = AppendTTLSuffix(keyStr, a.clock.Now(), ttl)

	var cachedBytes []byte
	if err := a.group.Get(ctx, keyStr, groupcache.AllocatingByteSliceSink(&cachedBytes)); err != nil {
		return zero, err
	}

	value, err := a.deserializeValue(cachedBytes)
	if err != nil {
		return zero, fmt.Errorf("cache: failed to deserialize value: %w", err)
	}

	return value, nil
}
