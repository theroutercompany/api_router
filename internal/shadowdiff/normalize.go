package shadowdiff

import "encoding/json"

// StripJSONKeys returns a normalizer that removes provided keys from top-level
// JSON objects and nested objects within arrays.
func StripJSONKeys(keys ...string) func([]byte) []byte {
	if len(keys) == 0 {
		return func(b []byte) []byte { return b }
	}

	keySet := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		keySet[key] = struct{}{}
	}

	return func(b []byte) []byte {
		if len(b) == 0 {
			return b
		}

		var payload interface{}
		if err := json.Unmarshal(b, &payload); err != nil {
			return b
		}

		stripKeys(payload, keySet)

		result, err := json.Marshal(payload)
		if err != nil {
			return b
		}
		return result
	}
}

func stripKeys(value interface{}, keySet map[string]struct{}) {
	switch v := value.(type) {
	case map[string]interface{}:
		for key := range keySet {
			delete(v, key)
		}
		for _, child := range v {
			stripKeys(child, keySet)
		}
	case []interface{}:
		for _, elem := range v {
			stripKeys(elem, keySet)
		}
	}
}
