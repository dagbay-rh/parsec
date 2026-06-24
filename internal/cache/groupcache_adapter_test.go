package cache_test

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/cache"
	"github.com/project-kessel/parsec/internal/clock"
)

type testEntry struct {
	Value string `json:"value"`
}

func newTestAdapter(t *testing.T, clk clock.Clock, ttl time.Duration, fetchCount *atomic.Int64) *cache.GroupcacheAdapter[string, *testEntry] {
	t.Helper()

	adapter, err := cache.NewGroupcacheAdapter(cache.GroupcacheAdapterConfig[string, *testEntry]{
		GroupName:      fmt.Sprintf("test-%s-%d", t.Name(), time.Now().UnixNano()),
		CacheSizeBytes: 1 << 20,
		Clock:          clk,
		TTL:            func() cache.TTL { return ttl },
		SerializeKey:   func(k string) (string, error) { return k, nil },
		DeserializeKey: func(s string) (string, error) { return s, nil },
		Fetch: func(_ context.Context, key string) (*testEntry, error) {
			fetchCount.Add(1)
			return &testEntry{Value: "fetched:" + key}, nil
		},
		SerializeValue: func(v *testEntry) ([]byte, error) {
			return json.Marshal(v)
		},
		DeserializeValue: func(b []byte) (*testEntry, error) {
			var entry testEntry
			if err := json.Unmarshal(b, &entry); err != nil {
				return nil, err
			}
			return &entry, nil
		},
	})
	if err != nil {
		t.Fatalf("NewGroupcacheAdapter failed: %v", err)
	}
	return adapter
}

func TestGroupcacheAdapter_CachesResults(t *testing.T) {
	clk := clock.NewFixtureClock(time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC))
	var fetchCount atomic.Int64
	adapter := newTestAdapter(t, clk, 5*time.Minute, &fetchCount)

	ctx := context.Background()

	result1, err := adapter.Get(ctx, "key-a")
	if err != nil {
		t.Fatalf("first Get failed: %v", err)
	}
	if result1.Value != "fetched:key-a" {
		t.Errorf("result = %q, want %q", result1.Value, "fetched:key-a")
	}
	if fetchCount.Load() != 1 {
		t.Errorf("fetch count = %d, want 1", fetchCount.Load())
	}

	result2, err := adapter.Get(ctx, "key-a")
	if err != nil {
		t.Fatalf("second Get failed: %v", err)
	}
	if result2.Value != "fetched:key-a" {
		t.Errorf("result = %q, want %q", result2.Value, "fetched:key-a")
	}
	if fetchCount.Load() != 1 {
		t.Errorf("fetch count = %d, want 1 (should be cached)", fetchCount.Load())
	}
}

func TestGroupcacheAdapter_DifferentKeysAreSeparate(t *testing.T) {
	clk := clock.NewFixtureClock(time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC))
	var fetchCount atomic.Int64
	adapter := newTestAdapter(t, clk, 5*time.Minute, &fetchCount)

	ctx := context.Background()

	_, err := adapter.Get(ctx, "key-a")
	if err != nil {
		t.Fatalf("Get key-a failed: %v", err)
	}

	_, err = adapter.Get(ctx, "key-b")
	if err != nil {
		t.Fatalf("Get key-b failed: %v", err)
	}

	if fetchCount.Load() != 2 {
		t.Errorf("fetch count = %d, want 2", fetchCount.Load())
	}
}

func TestGroupcacheAdapter_TTLBucketExpiry(t *testing.T) {
	clk := clock.NewFixtureClock(time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC))
	var fetchCount atomic.Int64
	adapter := newTestAdapter(t, clk, 5*time.Minute, &fetchCount)

	ctx := context.Background()

	_, err := adapter.Get(ctx, "key-a")
	if err != nil {
		t.Fatalf("first Get failed: %v", err)
	}
	if fetchCount.Load() != 1 {
		t.Fatalf("fetch count = %d, want 1", fetchCount.Load())
	}

	// Advance within the same TTL bucket — should still be cached
	clk.Advance(2 * time.Minute)
	_, err = adapter.Get(ctx, "key-a")
	if err != nil {
		t.Fatalf("Get within bucket failed: %v", err)
	}
	if fetchCount.Load() != 1 {
		t.Errorf("fetch count = %d, want 1 (same bucket)", fetchCount.Load())
	}

	// Advance past the TTL bucket boundary — cache key changes, triggers refetch
	clk.Advance(4 * time.Minute)
	_, err = adapter.Get(ctx, "key-a")
	if err != nil {
		t.Fatalf("Get after bucket change failed: %v", err)
	}
	if fetchCount.Load() != 2 {
		t.Errorf("fetch count = %d, want 2 (new bucket)", fetchCount.Load())
	}
}

func TestGroupcacheAdapter_ZeroTTLCachesIndefinitely(t *testing.T) {
	clk := clock.NewFixtureClock(time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC))
	var fetchCount atomic.Int64
	adapter := newTestAdapter(t, clk, 0, &fetchCount)

	ctx := context.Background()

	_, err := adapter.Get(ctx, "key-a")
	if err != nil {
		t.Fatalf("first Get failed: %v", err)
	}

	// Advance way past any reasonable TTL
	clk.Advance(24 * time.Hour)

	_, err = adapter.Get(ctx, "key-a")
	if err != nil {
		t.Fatalf("second Get failed: %v", err)
	}
	if fetchCount.Load() != 1 {
		t.Errorf("fetch count = %d, want 1 (no TTL = no expiry)", fetchCount.Load())
	}
}

func TestGroupcacheAdapter_FetchErrorPreventsCache(t *testing.T) {
	clk := clock.NewFixtureClock(time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC))

	adapter, err := cache.NewGroupcacheAdapter(cache.GroupcacheAdapterConfig[string, *testEntry]{
		GroupName:      fmt.Sprintf("test-%s-%d", t.Name(), time.Now().UnixNano()),
		CacheSizeBytes: 1 << 20,
		Clock:          clk,
		TTL:            func() cache.TTL { return 5 * time.Minute },
		SerializeKey:   func(k string) (string, error) { return k, nil },
		DeserializeKey: func(s string) (string, error) { return s, nil },
		Fetch: func(_ context.Context, _ string) (*testEntry, error) {
			return nil, fmt.Errorf("source unavailable")
		},
		SerializeValue: func(v *testEntry) ([]byte, error) {
			return json.Marshal(v)
		},
		DeserializeValue: func(b []byte) (*testEntry, error) {
			var entry testEntry
			return &entry, json.Unmarshal(b, &entry)
		},
	})
	if err != nil {
		t.Fatalf("NewGroupcacheAdapter failed: %v", err)
	}

	_, err = adapter.Get(context.Background(), "key-a")
	if err == nil {
		t.Fatal("expected error from failed fetch")
	}
}

func TestGroupcacheAdapter_MissingConfigReturnsError(t *testing.T) {
	tests := []struct {
		name   string
		config cache.GroupcacheAdapterConfig[string, *testEntry]
	}{
		{
			name:   "missing GroupName",
			config: cache.GroupcacheAdapterConfig[string, *testEntry]{},
		},
		{
			name: "missing SerializeKey",
			config: cache.GroupcacheAdapterConfig[string, *testEntry]{
				GroupName: "test-missing-sk",
			},
		},
		{
			name: "missing Fetch",
			config: cache.GroupcacheAdapterConfig[string, *testEntry]{
				GroupName:      "test-missing-fetch",
				SerializeKey:   func(k string) (string, error) { return k, nil },
				DeserializeKey: func(s string) (string, error) { return s, nil },
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := cache.NewGroupcacheAdapter(tt.config)
			if err == nil {
				t.Fatal("expected error for incomplete config")
			}
		})
	}
}
