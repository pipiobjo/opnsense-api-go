// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package capability

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Kind is the Go type a field's value has in this package.
type Kind int

const (
	// KindString: string. Also numbers that are not integers
	// (NumericField), so nothing is lost by rounding.
	KindString Kind = iota
	// KindBool: bool; "0"/"1" on the wire.
	KindBool
	// KindInt: int64; decimal on the wire.
	KindInt
	// KindList: []string; comma-separated on the wire, a selection map on
	// read for option fields.
	KindList
)

func (k Kind) String() string {
	if k < KindString || k > KindList {
		return fmt.Sprintf("Kind(%d)", int(k))
	}
	return [...]string{"string", "bool", "int", "list"}[k]
}

// Kind of a field variant.
func (f *Field) Kind() Kind {
	switch {
	case f.Multiple:
		return KindList
	case f.Base == "BooleanField":
		return KindBool
	case f.Base == "IntegerField" || f.Base == "AutoNumberField":
		return KindInt
	}
	return KindString
}

// StaticOptions reports whether Options is the complete list of allowed
// values: only for the core OptionField without derivation gaps. Subclasses
// (ServiceField, JsonKeyValueStoreField, ...) can add options at run time,
// and option groups are not represented exactly.
func (f *Field) StaticOptions() bool {
	return f.Type == "OptionField" && len(f.Gaps) == 0 && len(f.Options) > 0
}

// Encode turns a Go value into the wire string for this field, checking
// its type and static options. Accepted: bool, string, []string and the
// integer types; a string is accepted for every kind as the raw wire value
// if it fits the kind ("0"/"1" for booleans, digits for integers).
func (f *Field) Encode(v any) (string, error) {
	var s string
	switch x := v.(type) {
	case string:
		s = x
		switch f.Kind() {
		case KindBool:
			if s != "" && s != "0" && s != "1" {
				return "", errors.New(`not a boolean ("0" or "1")`)
			}
		case KindInt:
			if s != "" {
				if _, err := strconv.ParseInt(s, 10, 64); err != nil {
					return "", errors.New("not an integer")
				}
			}
		}
	case bool:
		if f.Kind() != KindBool {
			return "", fmt.Errorf("bool given for a %s field", f.Kind())
		}
		s = map[bool]string{true: "1", false: "0"}[x]
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		if f.Kind() != KindInt {
			return "", fmt.Errorf("integer given for a %s field", f.Kind())
		}
		s = fmt.Sprint(x)
	case []string:
		if f.Kind() != KindList {
			return "", fmt.Errorf("list given for a %s field", f.Kind())
		}
		for i, e := range x {
			if strings.Contains(e, ",") {
				return "", fmt.Errorf("list element %d contains a comma", i+1)
			}
		}
		s = strings.Join(x, ",")
	case nil:
		s = ""
	default:
		return "", fmt.Errorf("unsupported value type %T", v)
	}
	if err := f.checkOptions(s); err != nil {
		return "", err
	}
	return s, nil
}

// checkOptions: values of a field with a complete static option list must
// be among them (see StaticOptions). Others are left to the firewall.
func (f *Field) checkOptions(s string) error {
	if !f.StaticOptions() || s == "" {
		return nil
	}
	allowed := make(map[string]bool, len(f.Options))
	for _, o := range f.Options {
		allowed[o.Value] = true
	}
	vals := []string{s}
	if f.Multiple {
		vals = strings.Split(s, ",")
	}
	for i, v := range vals {
		if !allowed[v] {
			if f.Multiple {
				return fmt.Errorf("element %d is not an option (%s)", i+1, optionList(f.Options))
			}
			return fmt.Errorf("not an option (%s)", optionList(f.Options))
		}
	}
	return nil
}

func optionList(opts []Option) string {
	vals := make([]string, 0, len(opts))
	for _, o := range opts {
		vals = append(vals, o.Value)
	}
	if len(vals) > 12 {
		return strings.Join(vals[:12], ", ") + fmt.Sprintf(", ... %d more", len(vals)-12)
	}
	return strings.Join(vals, ", ")
}

// Wire returns the raw wire string of a value as read from the firewall:
// option fields arrive as {key: {value, selected}} and become the selected
// keys, comma-separated, in the server's order.
func (f *Field) Wire(raw any) (string, error) {
	switch x := raw.(type) {
	case nil:
		return "", nil
	case string:
		return x, nil
	case json.Number: // a number in JSON (rare); exact
		return x.String(), nil
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), nil
	case bool:
		return map[bool]string{true: "1", false: "0"}[x], nil
	case []any:
		// PHP encodes an option map with the keys "0", "1", ... as a JSON
		// list (seen for unbound advanced.logverbosity on 26.7.9): the
		// index is the key. An empty list is an empty selection.
		var keys []string
		for i, e := range x {
			opt, ok := e.(map[string]any)
			if !ok {
				return "", fmt.Errorf("unexpected list value")
			}
			if _, ok := opt["selected"]; !ok {
				return "", fmt.Errorf("unexpected list value")
			}
			if selected(opt["selected"]) {
				keys = append(keys, strconv.Itoa(i))
			}
		}
		return strings.Join(keys, ","), nil
	case map[string]any:
		var keys []string
		for k, v := range x {
			opt, _ := v.(map[string]any)
			if opt == nil {
				return "", fmt.Errorf("option %q is not an object", k)
			}
			if selected(opt["selected"]) {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys) // JSON objects have no order; sort for stable output
		return strings.Join(keys, ","), nil
	}
	return "", fmt.Errorf("unexpected value of type %T", raw)
}

// selected reads the "selected" flag of an option: 1, true or "1".
func selected(v any) bool {
	switch x := v.(type) {
	case json.Number:
		return x.String() == "1"
	case float64:
		return x == 1
	case bool:
		return x
	case string:
		return x == "1"
	}
	return false
}

// Decode turns a wire string into the field's Go value. An empty string
// is nil for bool and int fields (not set), an empty list for lists.
func (f *Field) Decode(s string) (any, error) {
	switch f.Kind() {
	case KindBool:
		switch s {
		case "":
			return nil, nil
		case "1":
			return true, nil
		case "0":
			return false, nil
		}
		return nil, errors.New("boolean field has a value other than 0, 1 or empty")
	case KindInt:
		if s == "" {
			return nil, nil
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return nil, errors.New("integer field has a value that is not an integer")
		}
		return n, nil
	case KindList:
		if s == "" {
			return []string{}, nil
		}
		return strings.Split(s, ","), nil
	}
	return s, nil
}

// SameWire compares a written and a read wire value: equal, or for list
// fields the same elements in any order (the server may reorder them).
func (f *Field) SameWire(sent, got string) bool {
	if sent == got {
		return true
	}
	if f.Kind() != KindList {
		return false
	}
	a, b := strings.Split(sent, ","), strings.Split(got, ",")
	if sent == "" {
		a = nil
	}
	if got == "" {
		b = nil
	}
	sort.Strings(a)
	sort.Strings(b)
	return strings.Join(a, ",") == strings.Join(b, ",")
}

// CustomWrite reports whether the field's type converts or normalizes
// values on write (gap custom-write): the stored value may differ from the
// one sent.
func (f *Field) CustomWrite() bool { return f != nil && slices.Contains(f.Gaps, GapCustomWrite) }

// CustomReadShape reports whether the field's type renders its value with
// its own code on read (gap custom-read-shape), so what get shows can
// differ from the stored value a search returns.
func (f *Field) CustomReadShape() bool {
	return f != nil && slices.Contains(f.Gaps, GapCustomReadShape)
}
