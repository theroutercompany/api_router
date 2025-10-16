package shadowdiff

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFixtures(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fixtures.json")
	json := `[
      {"name":"health","method":"GET","path":"/health","headers":{"x-test":"1"},"expectStatus":200}
    ]`

	if err := os.WriteFile(path, []byte(json), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	fixtures, err := LoadFixtures([]string{path})
	if err != nil {
		t.Fatalf("load fixtures: %v", err)
	}

	if len(fixtures) != 1 {
		t.Fatalf("expected 1 fixture, got %d", len(fixtures))
	}
	if fixtures[0].Headers["x-test"] != "1" {
		t.Fatalf("expected header value 1")
	}
}
