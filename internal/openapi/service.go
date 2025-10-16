package openapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/getkin/kin-openapi/openapi3"

	pkglog "github.com/theroutercompany/api_router/pkg/log"
)

const (
	defaultConfigFile = "openapi-merge.config.json"
	defaultDistFile   = "dist/openapi.json"
)

// DocumentProvider exposes the merged OpenAPI document.
type DocumentProvider interface {
	Document(ctx context.Context) ([]byte, error)
}

// Service merges OpenAPI fragments described in a config file and caches the result.
type Service struct {
	configPath string
	distPath   string

	mu    sync.Mutex
	cache *cacheEntry
}

type cacheEntry struct {
	raw     []byte
	modTime time.Time
}

// Option customises a Service.
type Option func(*Service)

// WithConfigPath overrides the config file used for merging OpenAPI fragments.
func WithConfigPath(path string) Option {
	return func(s *Service) {
		if path != "" {
			s.configPath = path
		}
	}
}

// WithDistPath overrides the location used to persist the merged OpenAPI document.
func WithDistPath(path string) Option {
	return func(s *Service) {
		if path != "" {
			s.distPath = path
		}
	}
}

// NewService constructs a Service with optional overrides.
func NewService(opts ...Option) *Service {
	s := &Service{
		configPath: resolveConfigPath(),
		distPath:   filepath.FromSlash(defaultDistFile),
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// Document returns the merged OpenAPI document in JSON form.
func (s *Service) Document(ctx context.Context) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if data, ok := s.cachedIfCurrent(); ok {
		return data, nil
	}

	if data, modTime, err := s.readDist(); err == nil {
		s.cache = &cacheEntry{raw: data, modTime: modTime}
		return clone(data), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read dist: %w", err)
	}

	doc, err := s.buildDocument(ctx)
	if err != nil {
		return nil, err
	}

	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode document: %w", err)
	}

	if err := s.persist(raw); err != nil {
		pkglog.Logger().Warnw("failed to persist merged openapi document", "error", err, "path", s.distPath)
		s.cache = &cacheEntry{raw: clone(raw), modTime: time.Time{}}
		return clone(raw), nil
	}

	modTime := fileModTime(s.distPath)
	s.cache = &cacheEntry{raw: clone(raw), modTime: modTime}

	return clone(raw), nil
}

func (s *Service) cachedIfCurrent() ([]byte, bool) {
	if s.cache == nil {
		return nil, false
	}
	info, err := os.Stat(s.distPath)
	if err != nil {
		return nil, false
	}
	if info.ModTime().Equal(s.cache.modTime) {
		return clone(s.cache.raw), true
	}
	return nil, false
}

func (s *Service) readDist() ([]byte, time.Time, error) {
	info, err := os.Stat(s.distPath)
	if err != nil {
		return nil, time.Time{}, err
	}

	data, err := os.ReadFile(s.distPath)
	if err != nil {
		return nil, time.Time{}, err
	}

	return data, info.ModTime(), nil
}

func (s *Service) buildDocument(ctx context.Context) (*openapi3.T, error) {
	cfg, baseDir, err := s.loadConfig()
	if err != nil {
		return nil, err
	}

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true

	docs := make([]*openapi3.T, 0, len(cfg.Inputs))
	for _, input := range cfg.Inputs {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		path := input.InputFile
		if !filepath.IsAbs(path) {
			path = filepath.Join(baseDir, path)
		}

		doc, err := loader.LoadFromFile(path)
		if err != nil {
			return nil, fmt.Errorf("load openapi fragment %s: %w", path, err)
		}
		docs = append(docs, doc)
	}

	merged, err := mergeDocuments(docs)
	if err != nil {
		return nil, err
	}

	return merged, nil
}

func (s *Service) persist(raw []byte) error {
	if s.distPath == "" {
		return errors.New("dist path not configured")
	}
	dir := filepath.Dir(s.distPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(s.distPath, raw, 0o644); err != nil {
		return err
	}
	return nil
}

func (s *Service) loadConfig() (*mergeConfig, string, error) {
	if s.configPath == "" {
		return nil, "", errors.New("config path not configured")
	}

	raw, err := os.ReadFile(s.configPath)
	if err != nil {
		return nil, "", fmt.Errorf("read config: %w", err)
	}

	var cfg mergeConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, "", fmt.Errorf("parse config: %w", err)
	}

	if len(cfg.Inputs) == 0 {
		return nil, "", errors.New("openapi merge configuration has no inputs")
	}

	return &cfg, filepath.Dir(s.configPath), nil
}

type mergeConfig struct {
	Inputs []mergeInput `json:"inputs"`
}

type mergeInput struct {
	InputFile string `json:"inputFile"`
}

func mergeDocuments(docs []*openapi3.T) (*openapi3.T, error) {
	if len(docs) == 0 {
		return nil, errors.New("no openapi documents to merge")
	}

	base := docs[0]

	if base.Paths == nil {
		base.Paths = openapi3.NewPaths()
	}
	if base.Components == nil {
		components := openapi3.NewComponents()
		base.Components = &components
	}

	for _, doc := range docs[1:] {
		if err := mergePaths(base.Paths, doc.Paths); err != nil {
			return nil, err
		}
		if err := mergeComponents(base.Components, doc.Components); err != nil {
			return nil, err
		}
		base.Tags = mergeTags(base.Tags, doc.Tags)
		base.Servers = mergeServers(base.Servers, doc.Servers)
		base.Security = mergeSecurity(base.Security, doc.Security)
	}

	return base, nil
}

func mergePaths(dst, src *openapi3.Paths) error {
	if src == nil {
		return nil
	}
	if dst == nil {
		return errors.New("destination paths not initialised")
	}

	dstMap := dst.Map()
	for path, item := range src.Map() {
		if _, exists := dstMap[path]; exists {
			return fmt.Errorf("duplicate path detected: %s", path)
		}
		dst.Set(path, item)
	}

	if len(src.Extensions) > 0 {
		if dst.Extensions == nil {
			dst.Extensions = make(map[string]interface{}, len(src.Extensions))
		}
		for key, value := range src.Extensions {
			if _, exists := dst.Extensions[key]; exists {
				return fmt.Errorf("duplicate path extension detected: %s", key)
			}
			dst.Extensions[key] = value
		}
	}

	return nil
}

func mergeComponents(dst, src *openapi3.Components) error {
	if src == nil {
		return nil
	}
	if dst == nil {
		return errors.New("destination components not initialised")
	}

	if err := mergeComponentMap(&dst.Schemas, src.Schemas, "schema"); err != nil {
		return err
	}
	if err := mergeComponentMap(&dst.Parameters, src.Parameters, "parameter"); err != nil {
		return err
	}
	if err := mergeComponentMap(&dst.Headers, src.Headers, "header"); err != nil {
		return err
	}
	if err := mergeComponentMap(&dst.RequestBodies, src.RequestBodies, "request body"); err != nil {
		return err
	}
	if err := mergeComponentMap(&dst.Responses, src.Responses, "response"); err != nil {
		return err
	}
	if err := mergeComponentMap(&dst.Examples, src.Examples, "example"); err != nil {
		return err
	}
	if err := mergeComponentMap(&dst.SecuritySchemes, src.SecuritySchemes, "security scheme"); err != nil {
		return err
	}
	if err := mergeComponentMap(&dst.Links, src.Links, "link"); err != nil {
		return err
	}
	if err := mergeComponentMap(&dst.Callbacks, src.Callbacks, "callback"); err != nil {
		return err
	}
	if err := mergeComponentMap(&dst.Extensions, src.Extensions, "extension"); err != nil {
		return err
	}

	return nil
}

func mergeComponentMap[M ~map[string]V, V any](dst *M, src M, label string) error {
	if len(src) == 0 {
		return nil
	}
	if *dst == nil {
		*dst = make(M, len(src))
	}
	for key, value := range src {
		if _, exists := (*dst)[key]; exists {
			return fmt.Errorf("duplicate %s detected: %s", label, key)
		}
		(*dst)[key] = value
	}
	return nil
}

func mergeTags(dst openapi3.Tags, src openapi3.Tags) openapi3.Tags {
	if len(src) == 0 {
		return dst
	}

	existing := make(map[string]struct{}, len(dst))
	for _, tag := range dst {
		if tag != nil {
			existing[tag.Name] = struct{}{}
		}
	}

	for _, tag := range src {
		if tag == nil {
			continue
		}
		if _, ok := existing[tag.Name]; ok {
			continue
		}
		dst = append(dst, tag)
		existing[tag.Name] = struct{}{}
	}
	return dst
}

func mergeServers(dst, src openapi3.Servers) openapi3.Servers {
	if len(src) == 0 {
		return dst
	}

	existing := make(map[string]struct{}, len(dst))
	for _, server := range dst {
		if server != nil {
			existing[server.URL] = struct{}{}
		}
	}

	for _, server := range src {
		if server == nil {
			continue
		}
		if _, ok := existing[server.URL]; ok {
			continue
		}
		dst = append(dst, server)
		existing[server.URL] = struct{}{}
	}
	return dst
}

func mergeSecurity(dst, src openapi3.SecurityRequirements) openapi3.SecurityRequirements {
	if len(src) == 0 {
		return dst
	}
	return append(dst, src...)
}

func resolveConfigPath() string {
	if path := os.Getenv("OPENAPI_MERGE_CONFIG_PATH"); path != "" {
		return path
	}
	return filepath.FromSlash(defaultConfigFile)
}

func fileModTime(path string) time.Time {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}

func clone(src []byte) []byte {
	if src == nil {
		return nil
	}
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}
