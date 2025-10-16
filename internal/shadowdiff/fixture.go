package shadowdiff

import (
	"encoding/json"
	"fmt"
	"os"
)

// Fixture represents a captured request/response expectation.
type Fixture struct {
	Name         string            `json:"name"`
	Method       string            `json:"method"`
	Path         string            `json:"path"`
	Headers      map[string]string `json:"headers"`
	Body         json.RawMessage   `json:"body"`
	ExpectStatus int               `json:"expectStatus"`
}

// LoadFixtures reads fixtures from disk.
func LoadFixtures(paths []string) ([]Fixture, error) {
	var fixtures []Fixture
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read fixture %s: %w", path, err)
		}

		var fileFixtures []Fixture
		if err := json.Unmarshal(data, &fileFixtures); err != nil {
			return nil, fmt.Errorf("decode fixture %s: %w", path, err)
		}
		fixtures = append(fixtures, fileFixtures...)
	}
	return fixtures, nil
}
