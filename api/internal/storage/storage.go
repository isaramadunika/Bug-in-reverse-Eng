// Package storage provides safe content-addressed storage for artifacts.
package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var (
	ErrNotFound   = errors.New("storage object not found")
	ErrInvalidKey = errors.New("invalid storage key")
)

type Storage interface {
	Put(ctx context.Context, key string, r io.Reader) (int64, error)
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	Delete(ctx context.Context, key string) error
	Stat(ctx context.Context, key string) (int64, error)
	LocalPath(key string) (string, error)
}

type LocalStorage struct {
	baseDir string
}

func NewLocal(baseDir string) (*LocalStorage, error) {
	abs, err := filepath.Abs(baseDir)
	if err != nil {
		return nil, fmt.Errorf("resolve storage dir: %w", err)
	}
	if err := os.MkdirAll(abs, 0700); err != nil {
		return nil, fmt.Errorf("create storage dir: %w", err)
	}
	return &LocalStorage{baseDir: abs}, nil
}

func (s *LocalStorage) resolve(key string) (string, error) {
	if key == "" || strings.Contains(key, "..") || strings.ContainsRune(key, 0) {
		return "", ErrInvalidKey
	}
	clean := filepath.Clean(filepath.FromSlash(key))
	if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
		return "", ErrInvalidKey
	}
	target := filepath.Join(s.baseDir, clean)
	// Guard against symlink or lexical escapes
	rel, err := filepath.Rel(s.baseDir, target)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", ErrInvalidKey
	}
	return target, nil
}

func (s *LocalStorage) Put(ctx context.Context, key string, r io.Reader) (int64, error) {
	target, err := s.resolve(key)
	if err != nil {
		return 0, err
	}
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return 0, fmt.Errorf("mkdir: %w", err)
	}

	// Atomic write: write to temp file then rename
	tmp, err := os.CreateTemp(dir, "upload-*.tmp")
	if err != nil {
		return 0, fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	n, err := io.Copy(tmp, r)
	if err != nil {
		return 0, fmt.Errorf("copy to temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return 0, fmt.Errorf("sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return 0, fmt.Errorf("close temp: %w", err)
	}

	if err := os.Rename(tmpName, target); err != nil {
		return 0, fmt.Errorf("commit file: %w", err)
	}
	return n, nil
}

func (s *LocalStorage) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	target, err := s.resolve(key)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(target)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return f, nil
}

func (s *LocalStorage) Delete(ctx context.Context, key string) error {
	target, err := s.resolve(key)
	if err != nil {
		return err
	}
	if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (s *LocalStorage) Stat(ctx context.Context, key string) (int64, error) {
	target, err := s.resolve(key)
	if err != nil {
		return 0, err
	}
	fi, err := os.Stat(target)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, ErrNotFound
		}
		return 0, err
	}
	return fi.Size(), nil
}

func (s *LocalStorage) LocalPath(key string) (string, error) {
	return s.resolve(key)
}
