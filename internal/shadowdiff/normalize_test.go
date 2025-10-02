package shadowdiff

import (
	"encoding/json"
	"testing"
)

func TestStripJSONKeysRemovesTopLevelKeys(t *testing.T) {
	normalizer := StripJSONKeys("timestamp", "uptime")

	input := []byte(`{"status":"ok","timestamp":"2024","uptime":1}`)
	output := normalizer(input)

	var obj map[string]interface{}
	if err := json.Unmarshal(output, &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if _, exists := obj["timestamp"]; exists {
		t.Fatalf("expected timestamp removed")
	}
	if _, exists := obj["uptime"]; exists {
		t.Fatalf("expected uptime removed")
	}
}

func TestStripJSONKeysHandlesArrays(t *testing.T) {
	normalizer := StripJSONKeys("checkedAt")

	input := []byte(`[{"checkedAt":"now","status":"ok"}]`)
	output := normalizer(input)

	var arr []map[string]interface{}
	if err := json.Unmarshal(output, &arr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(arr) != 1 {
		t.Fatalf("expected one element")
	}
	if _, exists := arr[0]["checkedAt"]; exists {
		t.Fatalf("expected checkedAt removed")
	}
}
