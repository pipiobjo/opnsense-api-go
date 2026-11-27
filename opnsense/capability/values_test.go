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
	writeF  = &Field{Type: "UpdateOnlyTextField", Base: "UpdateOnlyTextField", WriteOnly: true}
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
	if !writeF.WriteOnly || textF.WriteOnly {
		t.Error("WriteOnly")
	}
}

var (
	// AsList set field (kea option_data.domain_name_servers, chrony peers)
	asListF = &Field{Type: "NetworkField", Base: "BaseSetField", ReadShape: "select", List: &List{Separator: ",", Ordered: true}}
	// AliasContentField: newline-separated, order kept
	aliasF = &Field{Type: "AliasContentField", Base: "BaseField", ReadShape: "select", List: &List{Separator: "\n", Ordered: true}}
)

// Claim (DEV-1 of the review of 2026-11-24): a list field without
// "multiple" (AsList, alias content) is a list with the separator of the
// data, and where the firewall keeps the order written, the order counts:
// it is read in the answer's order and compared in order.
func TestListFields(t *testing.T) {
	if asListF.Kind() != KindList || aliasF.Kind() != KindList || multiF.Kind() != KindList || textF.Kind() != KindString {
		t.Fatal("kind")
	}
	if got, err := aliasF.Encode([]string{"192.0.2.2", "192.0.2.1"}); err != nil || got != "192.0.2.2\n192.0.2.1" {
		t.Errorf("alias encode = %q, %v", got, err)
	}
	if _, err := aliasF.Encode([]string{"a\nb"}); err == nil {
		t.Error("an element with the separator must fail")
	}
	if got, err := aliasF.Encode([]string{"a,b"}); err != nil || got != "a,b" {
		t.Errorf("a comma is no separator of alias content: %q, %v", got, err)
	}
	sel := map[string]any{
		"192.0.2.53": map[string]any{"value": "192.0.2.53", "selected": float64(1)},
		"192.0.2.1":  map[string]any{"value": "192.0.2.1", "selected": float64(1)},
	}
	if w, err := asListF.WireOrdered(sel, []string{"192.0.2.53", "192.0.2.1"}); err != nil || w != "192.0.2.53,192.0.2.1" {
		t.Errorf("the answer's order is kept: %q, %v", w, err)
	}
	if _, err := asListF.WireOrdered(sel, []string{"192.0.2.53"}); err == nil {
		t.Error("an order that does not name the selected keys must fail")
	}
	if w, _ := aliasF.WireOrdered(map[string]any{
		"b": map[string]any{"value": "b", "selected": float64(1)},
		"a": map[string]any{"value": "a", "selected": float64(1)},
		"c": map[string]any{"value": "c", "selected": float64(0)}, // getItem lists other aliases
	}, []string{"b", "a"}); w != "b\na" {
		t.Errorf("alias wire = %q", w)
	}
	// an empty AsList value reads as the key ""
	empty := map[string]any{"": map[string]any{"value": "", "selected": float64(1)}}
	if w, err := asListF.WireOrdered(empty, []string{""}); err != nil || w != "" {
		t.Errorf("empty list: %q, %v", w, err)
	}
	if v, _ := aliasF.Decode("b\na"); !reflect.DeepEqual(v, []string{"b", "a"}) {
		t.Errorf("decode = %#v", v)
	}
	if asListF.SameWire("b,a", "a,b") || !asListF.SameWire("b,a", "b,a") || !asListF.SameWire("a,a", "a") {
		t.Error("ordered lists compare in order; duplicates read back once")
	}
	if !multiF.SameWire("b,a", "a,b") {
		t.Error("an option list (order of the options) compares as a set")
	}
}

// SelectionOrder keeps the order the answer lists the selected keys in,
// for maps and for lists, at their paths; other objects are not selections.
func TestSelectionOrder(t *testing.T) {
	raw := []byte(`{"unbound":{"general":{"port":"53","servers":{"192.0.2.53":{"value":"192.0.2.53","selected":1},"192.0.2.1":{"value":"192.0.2.1","selected":1}},
	"iface":{"lan":{"value":"LAN","selected":0},"opt1":{"value":"OPT1","selected":"1"}},"level":[{"value":"0","selected":0},{"value":"1","selected":1}],"empty":{}}}}`)
	got, err := SelectionOrder(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"unbound.general.servers": {"192.0.2.53", "192.0.2.1"},
		"unbound.general.iface":   {"opt1"},
		"unbound.general.level":   {"1"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if _, err := SelectionOrder([]byte(`{"a":`)); err == nil {
		t.Error("broken JSON must fail")
	}
}

// Offered: every option of a selection map, the list shape (keys "0",
// "1", ... as PHP encodes them) included; a value that is no selection is
// an error.
func TestOffered(t *testing.T) {
	got, err := Offered([]any{map[string]any{"value": "low", "selected": "0"}, map[string]any{"value": "high", "selected": "1"}})
	if want := []Option{{Value: "0", Label: "low"}, {Value: "1", Label: "high"}}; err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("list shape: %+v, %v; want %+v", got, err, want)
	}
	for _, bad := range []any{"x", nil, map[string]any{"a": "b"}, map[string]any{"a": map[string]any{"value": "a"}}} {
		if _, err := Offered(bad); err == nil {
			t.Errorf("Offered(%v): no error", bad)
		}
	}
}

// Claim: the options of a core OptionField are the complete list unless
// the firewall decides them at run time; an invalid default does not
// change that (the spec's contract test checks the same rule).
func TestStaticOptions(t *testing.T) {
	gapped := func(codes ...string) *Field { f := *optF; f.Gaps = codes; return &f }
	for _, c := range []struct {
		name string
		f    *Field
		want bool
	}{
		{"OptionField", optF, true},
		{"invalid default", gapped(GapInvalidDefault), true},
		{"options at run time", gapped(GapOptionsDynamic), false},
		{"subclass", &Field{Type: `.\ServiceField`, Base: "BaseListField", Options: optF.Options}, false},
		{"no options", &Field{Type: "OptionField", Base: "BaseListField"}, false},
		{"relation", relF, false},
	} {
		if got := c.f.StaticOptions(); got != c.want {
			t.Errorf("%s: StaticOptions = %v, want %v", c.name, got, c.want)
		}
	}
}
