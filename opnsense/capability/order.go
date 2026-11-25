// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package capability

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
)

// SelectionOrder returns, for every selection map in a JSON answer (an
// object or list whose members are all {value, selected} objects), its
// selected keys in the order the answer lists them, keyed by the dotted
// path from the top of the answer ("unbound.hosts.aliases"). Decoding into
// map[string]any loses that order, and for a list field that keeps the
// order written (Field.Ordered) it is part of the value; pass the keys to
// Field.WireOrdered.
func SelectionOrder(raw []byte) (map[string][]string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	out := map[string][]string{}
	if _, _, err := walkSelections(dec, "", out); err != nil {
		return nil, err
	}
	return out, nil
}

// walkSelections reads one JSON value. It reports whether the value is an
// option ({..., "selected": x}) and whether that option is selected, and
// records every selection map below path in out.
func walkSelections(dec *json.Decoder, path string, out map[string][]string) (isOption, isSelected bool, err error) {
	tok, err := dec.Token()
	if err != nil {
		return false, false, err
	}
	delim, ok := tok.(json.Delim)
	if !ok || (delim != '{' && delim != '[') {
		return false, false, nil
	}
	all, n := true, 0
	keys := []string{}
	for i := 0; dec.More(); i++ {
		key := strconv.Itoa(i)
		if delim == '{' {
			kt, err := dec.Token()
			if err != nil {
				return false, false, err
			}
			key, _ = kt.(string)
			if key == "selected" {
				var v any
				if err := dec.Decode(&v); err != nil {
					return false, false, err
				}
				isOption, isSelected = true, selected(v)
				continue
			}
		}
		opt, sel, err := walkSelections(dec, join(path, key), out)
		if err != nil {
			return false, false, err
		}
		n++
		if !opt {
			all = false
		} else if sel {
			keys = append(keys, key)
		}
	}
	if end, err := dec.Token(); err != nil {
		return false, false, err
	} else if end != json.Delim(map[json.Delim]json.Delim{'{': '}', '[': ']'}[delim]) {
		return false, false, fmt.Errorf("unexpected %v", end)
	}
	if n > 0 && all && !isOption {
		out[path] = keys
	}
	return isOption, isSelected, nil
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}
