package cache

import (
	"io/fs"
	"path/filepath"
)

type MemoryFS struct {
	files map[string][]byte
}

func NewFS() *MemoryFS {
	return &MemoryFS{files: make(map[string][]byte)}
}

func (f *MemoryFS) Exists(path string) bool {
	_, found := f.files[filepath.Clean(path)]
	return found
}

func (f *MemoryFS) ReadFile(path string) ([]byte, error) {
	bytes := f.files[filepath.Clean(path)]
	if bytes == nil {
		return nil, fs.ErrNotExist
	}
	return bytes, nil
}

func (f *MemoryFS) WriteFile(path string, content []byte) (int, error) {
	bytes := f.files[filepath.Clean(path)]
	if bytes != nil {
		return 0, fs.ErrExist
	}
	f.files[filepath.Clean(path)] = content
	return len(content), nil
}
