package openapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDocumentMergesInputs(t *testing.T) {
	t.Helper()
	tmpDir := t.TempDir()

	specA := `
openapi: 3.1.0
info:
  title: Base
  version: 1.0.0
paths:
  /health:
    get:
      responses:
        '200':
          description: ok
components:
  schemas:
    Health:
      type: object
`
	specB := `
openapi: 3.1.0
info:
  title: Secondary
  version: 1.0.0
paths:
  /readyz:
    get:
      responses:
        '200':
          description: ready
components:
  schemas:
    Ready:
      type: object
`

	specAPath := filepath.Join(tmpDir, "spec-a.yaml")
	specBPath := filepath.Join(tmpDir, "spec-b.yaml")
	if err := os.WriteFile(specAPath, []byte(specA), 0o644); err != nil {
		t.Fatalf("write specA: %v", err)
	}
	if err := os.WriteFile(specBPath, []byte(specB), 0o644); err != nil {
		t.Fatalf("write specB: %v", err)
	}

	configPath := filepath.Join(tmpDir, "merge.json")
	config := []byte(`{
  "inputs": [
    { "inputFile": "spec-a.yaml" },
    { "inputFile": "spec-b.yaml" }
  ]
}`)
	if err := os.WriteFile(configPath, config, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	distPath := filepath.Join(tmpDir, "dist", "openapi.json")
	svc := NewService(
		WithConfigPath(configPath),
		WithDistPath(distPath),
	)

	raw, err := svc.Document(context.Background())
	if err != nil {
		t.Fatalf("Document() error: %v", err)
	}

	var doc struct {
		Paths map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal merged document: %v", err)
	}

	if _, ok := doc.Paths["/health"]; !ok {
		t.Fatalf("expected /health path present")
	}
	if _, ok := doc.Paths["/readyz"]; !ok {
		t.Fatalf("expected /readyz path present")
	}

	if _, err := os.Stat(distPath); err != nil {
		t.Fatalf("expected dist file to exist: %v", err)
	}
}

func TestDocumentUsesExistingDistWhenFresh(t *testing.T) {
	tmpDir := t.TempDir()

	distPath := filepath.Join(tmpDir, "dist", "openapi.json")
	if err := os.MkdirAll(filepath.Dir(distPath), 0o755); err != nil {
		t.Fatalf("mkdir dist: %v", err)
	}
	cached := []byte(`{"cached":true}`)
	if err := os.WriteFile(distPath, cached, 0o644); err != nil {
		t.Fatalf("write cached dist: %v", err)
	}
	// ensure known mod time
	if err := os.Chtimes(distPath, time.Now().Add(-time.Minute), time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	service := NewService(
		WithConfigPath(filepath.Join(tmpDir, "missing-config.json")), // will be ignored because dist exists
		WithDistPath(distPath),
	)

	raw, err := service.Document(context.Background())
	if err != nil {
		t.Fatalf("Document() error: %v", err)
	}
	if string(raw) != string(cached) {
		t.Fatalf("expected cached document to be returned")
	}
}

func TestDocumentErrorsWhenConfigMissing(t *testing.T) {
	service := NewService(
		WithConfigPath(filepath.Join(t.TempDir(), "missing.json")),
		WithDistPath(filepath.Join(t.TempDir(), "dist", "openapi.json")),
	)

	if _, err := service.Document(context.Background()); err == nil {
		t.Fatal("expected error when config is missing")
	}
}
