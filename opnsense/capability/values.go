// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package capability

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
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
	// KindList: []string; joined by Field.Separator on the wire, a
	// selection map on read.
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
	case f.Multiple || f.List != nil:
		return KindList
	case f.Base == "BooleanField":
		return KindBool
	case f.Base == "IntegerField" || f.Base == "AutoNumberField":
		return KindInt
	}
	return KindString
}

// Separator joins the elements of a list field on the wire: the one the
// data names, else "," (multiple option fields of older data).
func (f *Field) Separator() string {
	if f.List != nil && f.List.Separator != "" {
		return f.List.Separator
	}
	return ","
}

// Ordered reports whether the firewall keeps the order of a list field's
// elements as written; for other lists the order on read is its own.
func (f *Field) Ordered() bool { return f.List != nil && f.List.Ordered }

// StaticOptions reports whether Options is the complete list of allowed
// values: only for the core OptionField whose options the firewall does
// not decide at run time (gap options-dynamic). Subclasses
// (ServiceField, JsonKeyValueStoreField, ...) can add options at run time.
// The spec's contract test checks this claim with the same rule.
func (f *Field) StaticOptions() bool {
	return f.Type == "OptionField" && len(f.Options) > 0 && !slices.Contains(f.Gaps, GapOptionsDynamic)
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
		sep := f.Separator()
		for i, e := range x {
			if strings.Contains(e, sep) {
				return "", fmt.Errorf("list element %d contains the separator %q", i+1, sep)
			}
		}
		s = strings.Join(x, sep)
	case nil:
		s = ""
	default:
		return "", fmt.Errorf("unsupported value type %T", v)
	}
	if err := f.checkOptions(s); err != nil {
		return "", err
	}
	if err := f.checkValue(s); err != nil {
		return "", err
	}
	return s, nil
}

// checkValue: what the field's validators refuse that the type and the
// options do not show: the empty value of a required field (unless an
// empty write is ignored), and the limits of a non-empty value.
func (f *Field) checkValue(s string) error {
	if s == "" {
		if f.Required && !f.EmptyIgnored {
			return errors.New("a value is required")
		}
		return nil
	}
	// a single select (not multiple, no list) takes one key; the firewall
	// refuses a list of keys also where the options are decided at run
	// time (interfaces, certificates)
	if f.ReadShape == "select" && f.Kind() != KindList && strings.Contains(s, ",") &&
		!slices.ContainsFunc(f.Options, func(o Option) bool { return o.Value == s }) {
		return errors.New("takes one value, not a list")
	}
	l := f.Limits
	if l == nil {
		return nil
	}
	if l.Minimum != nil || l.Maximum != nil {
		n, err := strconv.ParseInt(s, 10, 64)
		switch {
		case err != nil:
			return errors.New("not an integer")
		case l.Minimum != nil && n < *l.Minimum:
			return fmt.Errorf("less than the minimum %d", *l.Minimum)
		case l.Maximum != nil && n > *l.Maximum:
			return fmt.Errorf("more than the maximum %d", *l.Maximum)
		}
	}
	if err := l.checkText(s, f.List); err != nil {
		return err
	}
	if l.Format != nil {
		return l.Format.check(s, f.List)
	}
	return nil
}

// checkText: forbidden characters, the pattern and the length.
func (l *Limits) checkText(s string, list *List) error {
	if i := strings.IndexAny(s, l.Forbidden); i >= 0 {
		return fmt.Errorf("contains %q, which the field forbids", s[i:i+1])
	}
	if l.Pattern == "" && l.MinLength == nil && l.MaxLength == nil {
		return nil
	}
	values := []string{s}
	if l.PerElement && list != nil {
		values = strings.Split(s, list.Separator)
	}
	for _, v := range values {
		n := int64(utf8.RuneCountInString(v))
		if l.Bytes {
			n = int64(len(v))
		}
		if l.MinLength != nil && n < *l.MinLength {
			return fmt.Errorf("shorter than %d", *l.MinLength)
		}
		if l.MaxLength != nil && n > *l.MaxLength {
			return fmt.Errorf("longer than %d", *l.MaxLength)
		}
		if l.Pattern == "" {
			continue
		}
		re, err := pattern(l.Pattern)
		if err != nil {
			return nil // a pattern this Go cannot run: left to the firewall
		}
		if l.Bytes {
			v = latin1(v)
		}
		if loc := re.FindStringIndex(v); loc == nil || loc[0] != 0 || loc[1] != len(v) {
			return fmt.Errorf("does not match the pattern %s", l.Pattern)
		}
	}
	return nil
}

// latin1: each byte one character, as PCRE sees a value without the u
// modifier.
func latin1(v string) string {
	r := make([]rune, len(v))
	for i := 0; i < len(v); i++ {
		r[i] = rune(v[i])
	}
	return string(r)
}

var patterns sync.Map // pattern -> *regexp.Regexp or error

// pattern compiles a Limits.Pattern once.
func pattern(p string) (*regexp.Regexp, error) {
	if v, ok := patterns.Load(p); ok {
		if re, ok := v.(*regexp.Regexp); ok {
			return re, nil
		}
		return nil, v.(error)
	}
	re, err := regexp.Compile(p)
	if err != nil {
		patterns.Store(p, err)
		return nil, err
	}
	patterns.Store(p, re)
	return re, nil
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
	if f.Kind() == KindList {
		vals = strings.Split(s, f.Separator())
	}
	for i, v := range vals {
		if !allowed[v] {
			if f.Kind() == KindList {
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
// list fields arrive as {key: {value, selected}} and become the selected
// keys joined by the separator. A decoded JSON object has lost its order,
// so the keys are sorted; for a field whose order counts (Ordered) use
// WireOrdered with the order of the answer (SelectionOrder).
func (f *Field) Wire(raw any) (string, error) {
	return f.WireOrdered(raw, nil)
}

// WireOrdered is Wire with the selected keys of a selection map in the
// order the answer listed them (from SelectionOrder); nil sorts them. The
// order must name exactly the selected keys.
func (f *Field) WireOrdered(raw any, order []string) (string, error) {
	sep := f.Separator()
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
		return joinSelection(keys, sep), nil
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
		sort.Strings(keys)
		keys = f.singleSelection(keys)
		if order != nil {
			o := slices.Clone(order)
			sort.Strings(o)
			if !slices.Equal(o, keys) {
				return "", fmt.Errorf("order %q does not name the selected keys %q", order, keys)
			}
			keys = order
		}
		return joinSelection(keys, sep), nil
	}
	return "", fmt.Errorf("unexpected value of type %T", raw)
}

// joinSelection joins selected keys; an AsList field with an empty value
// reads as the single key "", which is the empty list.
func joinSelection(keys []string, sep string) string {
	if len(keys) == 1 && keys[0] == "" {
		return ""
	}
	return strings.Join(keys, sep)
}

// singleSelection: a single select that marks the empty choice and one
// key holds that key. OPNsense 25.7 marks the empty choice for every
// value PHP's empty() calls empty, "0" included (spec
// docs/capabilities.md, "List fields").
func (f *Field) singleSelection(keys []string) []string {
	if f.Kind() != KindList && len(keys) == 2 && keys[0] == "" {
		return keys[1:]
	}
	return keys
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
		return strings.Split(s, f.Separator()), nil
	}
	return s, nil
}

// SameWire compares a written and a read wire value: equal; for list
// fields the same elements, in the same order where the firewall keeps it
// (Ordered), else in any order. Elements are unique on read (the keys of
// the selection map), so a duplicate written once reads back once.
func (f *Field) SameWire(sent, got string) bool {
	if sent == got {
		return true
	}
	if f.Kind() != KindList {
		return false
	}
	sep := f.Separator()
	a, b := uniq(strings.Split(sent, sep)), uniq(strings.Split(got, sep))
	if sent == "" {
		a = nil
	}
	if got == "" {
		b = nil
	}
	if !f.Ordered() {
		sort.Strings(a)
		sort.Strings(b)
	}
	return slices.Equal(a, b)
}

// uniq keeps the first of equal elements, in order.
func uniq(l []string) []string {
	out := l[:0:0]
	for _, e := range l {
		if !slices.Contains(out, e) {
			out = append(out, e)
		}
	}
	return out
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

// Offered returns every option of a selection map as read from the
// firewall ({key: {value, selected}}), sorted by key: the static options
// and those the firewall fills in at runtime (certificates, interfaces,
// other entries). The empty key (no selection) is left out. A value that
// is not a selection map is an error: the field has no options to offer.
func Offered(raw any) ([]Option, error) {
	var out []Option
	switch x := raw.(type) {
	case []any:
		// an option map with the keys "0", "1", ... arrives as a list (Wire)
		for i, e := range x {
			opt, ok := e.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("unexpected list value")
			}
			label, _ := opt["value"].(string)
			out = append(out, Option{Value: strconv.Itoa(i), Label: label})
		}
		return out, nil
	case map[string]any:
		for k, v := range x {
			opt, _ := v.(map[string]any)
			if opt == nil {
				return nil, fmt.Errorf("option %q is not an object", k)
			}
			if _, ok := opt["selected"]; !ok {
				return nil, fmt.Errorf("option %q is not an object", k)
			}
			if k == "" {
				continue
			}
			label, _ := opt["value"].(string)
			out = append(out, Option{Value: k, Label: label})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Value < out[j].Value })
		return out, nil
	}
	return nil, fmt.Errorf("not a selection: a value of type %T", raw)
}
