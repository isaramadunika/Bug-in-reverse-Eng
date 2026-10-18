package ratelimit

import (
	"context"
	"testing"
	"time"
)

func TestMemoryAllow(t *testing.T) {
	m := NewMemory()
	now := time.Unix(1000, 0)
	m.now = func() time.Time { return now }
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if ok, _, _ := m.Allow(ctx, "k", 3, time.Minute); !ok {
			t.Fatalf("request %d should pass", i)
		}
	}
	ok, retry, _ := m.Allow(ctx, "k", 3, time.Minute)
	if ok || retry <= 0 {
		t.Fatalf("4th request should be limited, retry=%v", retry)
	}
	now = now.Add(61 * time.Second)
	if ok, _, _ := m.Allow(ctx, "k", 3, time.Minute); !ok {
		t.Fatal("window should reset")
	}
}

func TestMemoryOnceAndReset(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	if ok, _ := m.Once(ctx, "code", time.Minute); !ok {
		t.Fatal("first use should succeed")
	}
	if ok, _ := m.Once(ctx, "code", time.Minute); ok {
		t.Fatal("replay should fail")
	}
	m.Allow(ctx, "x", 1, time.Minute)
	if ok, _, _ := m.Allow(ctx, "x", 1, time.Minute); ok {
		t.Fatal("should be limited")
	}
	_ = m.Reset(ctx, "x")
	if ok, _, _ := m.Allow(ctx, "x", 1, time.Minute); !ok {
		t.Fatal("reset should clear")
	}
}
