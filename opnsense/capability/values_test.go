// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package capability

import (
	"reflect"
	"testing"
)

var (
	boolF   = &Field{Type: "BooleanField", Base: "BooleanField"}
	intF    = &Field{Type: "IntegerField", Base: "IntegerField"}
	textF   = &Field{Type: "TextField", Base: "TextField"}
	optF    = &Field{Type: "OptionField", Base: "BaseListField", ReadShape: "select", Options: []Option{{Value: "a"}, {Value: "b"}}}
	multiF  = &Field{Type: "OptionField", Base: "BaseListField", ReadShape: "select", Multiple: true, Options: []Option{{Value: "a"}, {Value: "b"}, {Value: "c"}}}
	relF    = &Field{Type: "ModelRelationField", Base: "BaseListField", ReadShape: "select"} // dynamic options
	writeF  = &Field{Type: "UpdateOnlyTextField", Base: "UpdateOnlyTextField"}
	numberF = &Field{Type: "NumericField", Base: "NumericField"}
)

func TestEncode(t *testing.T) {
	ok := []struct {
		f    *Field
		v    any
		want string
	}{
		{boolF, true, "1"}, {boolF, false, "0"}, {boolF, "1", "1"},
		{intF, int64(42), "42"}, {intF, 7, "7"}, {intF, "-3", "-3"}, {intF, "", ""}, {boolF, "", ""},
		{textF, "x", "x"}, {textF, nil, ""},
		{optF, "b", "b"}, {optF, "", ""},
		{multiF, []string{"a", "c"}, "a,c"}, {multiF, []string{}, ""},
		{relF, "8d3f-uuid", "8d3f-uuid"},
		{numberF, "1.5", "1.5"},
	}
	for _, c := range ok {
		got, err := c.f.Encode(c.v)
		if err != nil || got != c.want {
			t.Errorf("Encode(%s, %#v) = %q, %v; want %q", c.f.Type, c.v, got, err, c.want)
		}
	}
	bad := []struct {
		f *Field
		v any
	}{
		{textF, true}, {boolF, 1}, {intF, []string{"1"}}, {textF, []string{"a"}},
		{optF, "z"}, {multiF, []string{"a", "z"}}, {multiF, []string{"a,b"}}, {textF, 1.5},
		{boolF, "yes"}, {boolF, "true"}, {intF, "high"}, {intF, "1.5"},
	}
	for _, c := range bad {
		if got, err := c.f.Encode(c.v); err == nil {
			t.Errorf("Encode(%s, %#v) = %q, want an error", c.f.Type, c.v, got)
		}
	}
}

func TestWireAndDecode(t *testing.T) {
	sel := map[string]any{
		"a": map[string]any{"value": "A", "selected": float64(0)},
		"b": map[string]any{"value": "B", "selected": float64(1)},
		"c": map[string]any{"value": "C", "selected": float64(1)},
	}
	cases := []struct {
		f    *Field
		raw  any
		wire string
		val  any
	}{
		{boolF, "1", "1", true}, {boolF, "", "", nil},
		{intF, "42", "42", int64(42)}, {intF, "", "", nil},
		{textF, "x", "x", "x"},
		{multiF, sel, "b,c", []string{"b", "c"}},
		{multiF, []any{}, "", []string{}},
		{optF, map[string]any{"a": map[string]any{"value": "A", "selected": float64(1)}}, "a", "a"},
		{relF, map[string]any{"": map[string]any{"value": "none", "selected": true}}, "", ""},
		// options with keys "0".."n" arrive as a JSON list
		{optF, []any{map[string]any{"value": "Level 0", "selected": float64(0)}, map[string]any{"value": "Level 1", "selected": float64(1)}}, "1", "1"},
		{multiF, []any{map[string]any{"value": "A", "selected": true}, map[string]any{"value": "B", "selected": false}, map[string]any{"value": "C", "selected": "1"}}, "0,2", []string{"0", "2"}},
	}
	for _, c := range cases {
		w, err := c.f.Wire(c.raw)
		if err != nil || w != c.wire {
			t.Errorf("Wire(%s, %v) = %q, %v; want %q", c.f.Type, c.raw, w, err, c.wire)
			continue
		}
		v, err := c.f.Decode(w)
		if err != nil || !reflect.DeepEqual(v, c.val) {
			t.Errorf("Decode(%s, %q) = %#v, %v; want %#v", c.f.Type, w, v, err, c.val)
		}
	}
	if _, err := boolF.Decode("yes"); err == nil {
		t.Error("a boolean with another value must fail")
	}
	if _, err := textF.Wire([]any{"a", "b"}); err == nil {
		t.Error("a list that is not an option list must fail")
	}
	if _, err := intF.Decode("1.5"); err == nil {
		t.Error("an integer with a fraction must fail")
	}
}

func TestSameWire(t *testing.T) {
	if !multiF.SameWire("a,b", "b,a") || multiF.SameWire("a,b", "a") || !multiF.SameWire("", "") {
		t.Error("lists compare as sets")
	}
	if textF.SameWire("a,b", "b,a") {
		t.Error("text compares exactly")
	}
	if !writeF.WriteOnly() || textF.WriteOnly() {
		t.Error("WriteOnly")
	}
}
