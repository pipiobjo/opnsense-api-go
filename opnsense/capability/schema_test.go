// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package capability

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Keys of the format the client deliberately does not read, with the
// reason. Everything else in the schema must have a field in the model, so
// a key added to the format is either used or listed here on purpose.
var ignoredKeys = map[string]string{
	// list fields (field.list, field.empty_ignored): the client still
	// encodes lists by "multiple"; the list encoding change reads them
	"list":          "list encoding not yet read",
	"separator":     "list encoding not yet read",
	"ordered":       "list encoding not yet read",
	"empty_ignored": "list encoding not yet read",
}

// schemaKeys returns every property name the JSON Schema defines, at any
// depth. Map keys (resource IDs, versions, hashes) are additionalProperties
// or patternProperties and not included. The schema comes from the test
// data, or with OPNSENSE_CAPABILITIES from the data the CI run downloaded
// (ci.yml, job data): a key the spec added since the test data was copied
// fails there, before a consumer silently ignores it.
func schemaKeys(t *testing.T) map[string]bool {
	t.Helper()
	dir := "testdata/catalog"
	if d := os.Getenv("OPNSENSE_CAPABILITIES"); d != "" {
		dir = d
	}
	t.Logf("schema: %s", dir)
	b, err := os.ReadFile(filepath.Join(dir, "capability.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	keys := map[string]bool{}
	var walk func(v any)
	walk = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			if p, ok := v["properties"].(map[string]any); ok {
				for k := range p {
					keys[k] = true
				}
			}
			for _, c := range v {
				walk(c)
			}
		case []any:
			for _, c := range v {
				walk(c)
			}
		}
	}
	walk(doc)
	return keys
}

// modelKeys returns the JSON names of every field reachable from the types
// a loaded Set exposes.
func modelKeys() map[string]bool {
	keys := map[string]bool{}
	seen := map[reflect.Type]bool{}
	var walk func(t reflect.Type)
	walk = func(t reflect.Type) {
		for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Map {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct || seen[t] {
			return
		}
		seen[t] = true
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if !f.IsExported() || name == "" || name == "-" {
				continue
			}
			keys[name] = true
			walk(f.Type)
		}
	}
	walk(reflect.TypeOf(Catalog{}))
	walk(reflect.TypeOf(Doc{}))
	return keys
}

// TestModelMatchesSchema: the client's model is a hand-written copy of the
// format. A key in the schema the model neither reads nor lists in
// ignoredKeys, or a key the model reads that the schema does not define,
// fails here, so the two cannot drift apart unnoticed.
func TestModelMatchesSchema(t *testing.T) {
	schema, model := schemaKeys(t), modelKeys()
	if len(schema) < 20 {
		t.Fatalf("only %d keys found in the schema; the walk is broken", len(schema))
	}
	var unread, unknown, stale []string
	for k := range schema {
		if !model[k] && ignoredKeys[k] == "" {
			unread = append(unread, k)
		}
	}
	for k := range model {
		if !schema[k] {
			unknown = append(unknown, k)
		}
	}
	for k := range ignoredKeys {
		if !schema[k] || model[k] {
			stale = append(stale, k)
		}
	}
	sort.Strings(unread)
	sort.Strings(unknown)
	sort.Strings(stale)
	if len(unread) > 0 {
		t.Errorf("keys of the format the model does not read (add them, or to ignoredKeys with a reason): %v", unread)
	}
	if os.Getenv("OPNSENSE_CAPABILITIES") != "" {
		// published data may be older than the model: reading a key it
		// does not have yet is harmless; ignoring one it has is not
		return
	}
	if len(unknown) > 0 {
		t.Errorf("keys the model reads that the format does not define: %v", unknown)
	}
	if len(stale) > 0 {
		t.Errorf("ignoredKeys entries that are read or no longer in the format: %v", stale)
	}
}
