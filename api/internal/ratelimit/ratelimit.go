// Package ratelimit provides fixed-window counters backed by Redis, with an
// in-memory implementation for single-instance development and tests.
package ratelimit

import (
	"context"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

type Limiter interface {
	// Allow increments the counter for key and reports whether it is within limit.
	Allow(ctx context.Context, key string, limit int, window time.Duration) (ok bool, retryAfter time.Duration, err error)
	// Once returns true the first time key is seen within ttl (replay protection).
	Once(ctx context.Context, key string, ttl time.Duration) (bool, error)
	// Reset clears a counter (e.g. after a successful login).
	Reset(ctx context.Context, key string) error
	Ping(ctx context.Context) error
}

// ---- Redis ----

type Redis struct{ c *redis.Client }

func NewRedis(url string) (*Redis, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}
	return &Redis{c: redis.NewClient(opt)}, nil
}

var incrScript = redis.NewScript(`
local v = redis.call('INCR', KEYS[1])
if v == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
return {v, redis.call('PTTL', KEYS[1])}
`)

func (r *Redis) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, time.Duration, error) {
	res, err := incrScript.Run(ctx, r.c, []string{"rl:" + key}, window.Milliseconds()).Int64Slice()
	if err != nil {
		return false, 0, err
	}
	if res[0] > int64(limit) {
		return false, time.Duration(res[1]) * time.Millisecond, nil
	}
	return true, 0, nil
}

func (r *Redis) Once(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	return r.c.SetNX(ctx, "once:"+key, 1, ttl).Result()
}

func (r *Redis) Reset(ctx context.Context, key string) error {
	return r.c.Del(ctx, "rl:"+key).Err()
}

func (r *Redis) Ping(ctx context.Context) error { return r.c.Ping(ctx).Err() }

// ---- Memory ----

type entry struct {
	n       int
	expires time.Time
}

type Memory struct {
	mu  sync.Mutex
	m   map[string]*entry
	now func() time.Time
}

func NewMemory() *Memory { return &Memory{m: map[string]*entry{}, now: time.Now} }

func (m *Memory) get(key string, window time.Duration) *entry {
	now := m.now()
	e, ok := m.m[key]
	if !ok || now.After(e.expires) {
		e = &entry{expires: now.Add(window)}
		m.m[key] = e
	}
	return e
}

func (m *Memory) Allow(_ context.Context, key string, limit int, window time.Duration) (bool, time.Duration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.get("rl:"+key, window)
	e.n++
	if e.n > limit {
		return false, e.expires.Sub(m.now()), nil
	}
	return true, 0, nil
}

func (m *Memory) Once(_ context.Context, key string, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.get("once:"+key, ttl)
	e.n++
	return e.n == 1, nil
}

func (m *Memory) Reset(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.m, "rl:"+key)
	return nil
}

func (m *Memory) Ping(context.Context) error { return nil }
