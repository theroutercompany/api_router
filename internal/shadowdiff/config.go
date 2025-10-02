package shadowdiff

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config defines the inputs required to run a shadow diff session.
type Config struct {
	NodeBaseURL string   `json:"nodeBaseUrl"`
	GoBaseURL   string   `json:"goBaseUrl"`
	Fixtures    []string `json:"fixtures"`
	Concurrency int      `json:"concurrency"`
}

// LoadConfig reads configuration from a JSON file.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}

	if cfg.NodeBaseURL == "" || cfg.GoBaseURL == "" {
		return Config{}, fmt.Errorf("nodeBaseUrl and goBaseUrl are required")
	}

	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 4
	}

	return cfg, nil
}
