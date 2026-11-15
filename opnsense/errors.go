// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package opnsense

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/pipiobjo/opnsense-api-go/internal/transport"
)

// ErrUnauthorized: key and secret were rejected, or the key lacks the
// privilege for the endpoint.
var ErrUnauthorized = transport.ErrUnauthorized

// ErrNotFound: the entry does not exist (anymore).
var ErrNotFound = errors.New("opnsense: entry not found")

// HTTPError is a response other than 2xx.
type HTTPError = transport.HTTPError

// ErrNotAvailable: the resource does not exist on this firewall, because
// the package is not installed or its version does not have it.
type ErrNotAvailable struct {
	Resource    string
	Package     string   // package that provides it ("" if no package does)
	Have        string   // installed version, "" if not installed
	AvailableIn []string // package versions that have it
}

func (e *ErrNotAvailable) Error() string {
	switch {
	case e.Package == "":
		return fmt.Sprintf("opnsense: resource %s is not in the capability data", e.Resource)
	case e.Have == "":
		return fmt.Sprintf("opnsense: resource %s needs package %s, which is not installed", e.Resource, e.Package)
	}
	return fmt.Sprintf("opnsense: resource %s is not available in %s %s (available in %s)",
		e.Resource, e.Package, e.Have, versionList(e.AvailableIn))
}

// ErrFieldNotAvailable: the field does not exist in the firewall's version.
// Sending it would be silently ignored by OPNsense, so it is never sent.
type ErrFieldNotAvailable struct {
	Resource, Field string
	Package, Have   string
	AvailableIn     []string // package versions that have the field
}

func (e *ErrFieldNotAvailable) Error() string {
	if len(e.AvailableIn) == 0 {
		return fmt.Sprintf("opnsense: %s has no field %q", e.Resource, e.Field)
	}
	return fmt.Sprintf("opnsense: field %q of %s is not available in %s %s (available in %s)",
		e.Field, e.Resource, e.Package, e.Have, versionList(e.AvailableIn))
}

// ErrInvalid: values failed the checks before sending (type, option,
// required field).
type ErrInvalid struct {
	Resource string
	Problems map[string]string // field -> problem
}

func (e *ErrInvalid) Error() string {
	return fmt.Sprintf("opnsense: invalid values for %s: %s", e.Resource, joinMap(e.Problems))
}

// ErrValidation: the firewall rejected the values (result "failed").
type ErrValidation struct {
	Resource string
	Fields   map[string]string // field -> message from the firewall
	Body     string            // the raw answer when it names no field
}

func (e *ErrValidation) Error() string {
	if len(e.Fields) == 0 {
		return fmt.Sprintf("opnsense: %s rejected: %s", e.Resource, e.Body)
	}
	return fmt.Sprintf("opnsense: %s rejected: %s", e.Resource, joinMap(e.Fields))
}

// FieldDiff is one field that did not read back as written.
type FieldDiff struct {
	Field     string
	Sent, Got string // wire values
}

// ErrNotApplied: the firewall answered "saved", but reading the object
// back shows other values. Typical causes: the field does not exist in this
// version after all, or the server normalises the value.
type ErrNotApplied struct {
	Resource, ID string
	Diffs        []FieldDiff
}

func (e *ErrNotApplied) Error() string {
	parts := make([]string, 0, len(e.Diffs))
	for _, d := range e.Diffs {
		parts = append(parts, fmt.Sprintf("%s: sent %q, read %q", d.Field, d.Sent, d.Got))
	}
	id := ""
	if e.ID != "" {
		id = " " + e.ID
	}
	return fmt.Sprintf("opnsense: %s%s saved but not applied as sent: %s", e.Resource, id, strings.Join(parts, "; "))
}

func versionList(vs []string) string {
	if len(vs) == 0 {
		return "no known version"
	}
	if len(vs) > 6 {
		return strings.Join(vs[:3], ", ") + ", ..., " + strings.Join(vs[len(vs)-2:], ", ")
	}
	return strings.Join(vs, ", ")
}

func joinMap(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+": "+m[k])
	}
	return strings.Join(parts, "; ")
}
