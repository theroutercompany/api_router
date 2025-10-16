package shadowdiff

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigSetsDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	data := `{"nodeBaseUrl":"http://node","goBaseUrl":"http://go","fixtures":["f.json"]}`

	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.Concurrency != 4 {
		t.Fatalf("expected default concurrency 4, got %d", cfg.Concurrency)
	}
}

func TestLoadConfigRequiresBaseURLs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	data := `{"fixtures":[]}`

	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := LoadConfig(path); err == nil {
		t.Fatalf("expected error when base URLs missing")
	}
}
