// Package testvec loads the test vectors dumped from the reference implementation
// (scripts/gen_vectors.py -> testdata/vectors.json).
package testvec

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/dl"
)

// Load returns the vectors.
func Load(t testing.TB) map[string]json.RawMessage {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	b, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "testdata", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// Get decodes one vector into v.
func Get(t testing.TB, all map[string]json.RawMessage, key string, v any) {
	t.Helper()
	raw, ok := all[key]
	if !ok {
		t.Fatalf("no vector %q", key)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("vector %q: %v", key, err)
	}
}

// Hex decodes hex.
func Hex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Value converts a JSON data-list value ({"s": hex}, {"b": hex}, arrays) to a dl.Value.
func Value(t testing.TB, raw json.RawMessage) dl.Value {
	t.Helper()
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) == nil {
		items := make([]dl.Value, len(list))
		for i, r := range list {
			items[i] = Value(t, r)
		}
		return dl.L(items...)
	}
	var obj map[string]string
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("bad value %s", raw)
	}
	if s, ok := obj["s"]; ok {
		return dl.S(string(Hex(t, s)))
	}
	return dl.B(Hex(t, obj["b"]))
}
