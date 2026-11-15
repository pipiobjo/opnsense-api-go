// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package capability

import (
	"fmt"
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

// WriteOnly reports fields the server accepts but never returns.
func (f *Field) WriteOnly() bool {
	return f.Type == "UpdateOnlyTextField" || f.Base == "UpdateOnlyTextField"
}

// ServerSet reports fields the firewall fills itself.
func (f *Field) ServerSet() bool {
	return f.Base == "UniqueIdField" || f.Base == "AutoNumberField"
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
				return "", fmt.Errorf("%q is not a boolean (\"0\" or \"1\")", s)
			}
		case KindInt:
			if s != "" {
				if _, err := strconv.ParseInt(s, 10, 64); err != nil {
					return "", fmt.Errorf("%q is not an integer", s)
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
		for _, e := range x {
			if strings.Contains(e, ",") {
				return "", fmt.Errorf("list element %q contains a comma", e)
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

// checkOptions: values of a field with static options must be among them.
// Fields without static options (dynamic lists such as interfaces) are not
// checked here; the firewall validates them.
func (f *Field) checkOptions(s string) error {
	if len(f.Options) == 0 || s == "" {
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
	for _, v := range vals {
		if !allowed[v] {
			return fmt.Errorf("%q is not an option (%s)", v, optionList(f.Options))
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
	case float64: // a number in JSON (rare)
		return strconv.FormatFloat(x, 'f', -1, 64), nil
	case bool:
		return map[bool]string{true: "1", false: "0"}[x], nil
	case []any:
		if len(x) == 0 { // PHP's empty array for an empty selection
			return "", nil
		}
		return "", fmt.Errorf("unexpected list value")
	case map[string]any:
		var keys []string
		for k, v := range x {
			opt, _ := v.(map[string]any)
			if opt == nil {
				return "", fmt.Errorf("option %q is not an object", k)
			}
			if sel, _ := opt["selected"].(float64); sel == 1 {
				keys = append(keys, k)
			} else if sel, _ := opt["selected"].(bool); sel {
				keys = append(keys, k)
			} else if sel, _ := opt["selected"].(string); sel == "1" {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys) // JSON objects have no order; sort for stable output
		return strings.Join(keys, ","), nil
	}
	return "", fmt.Errorf("unexpected value of type %T", raw)
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
		return nil, fmt.Errorf("boolean field has value %q", s)
	case KindInt:
		if s == "" {
			return nil, nil
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("integer field has value %q", s)
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
