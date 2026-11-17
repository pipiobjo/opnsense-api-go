// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package opnsense

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/pipiobjo/opnsense-api-go/internal/transport"
	"github.com/pipiobjo/opnsense-api-go/opnsense/capability"
)

// ErrUnauthorized: key and secret were rejected (HTTP 401).
var ErrUnauthorized = transport.ErrUnauthorized

// ErrForbidden: the key is valid but lacks the privilege (HTTP 403).
var ErrForbidden = transport.ErrForbidden

// ErrOutcomeUnknown: a change was sent, but its answer was lost, unreadable
// or a server error. It may have been saved, so the resource's apply
// endpoint is marked pending. After Add the new entry's ID is unknown: list
// the entries to find it before adding again.
var ErrOutcomeUnknown = transport.ErrOutcomeUnknown

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
	// PluginsUnknown: the API key may not read the plugin list (no firmware
	// privilege), so the client cannot tell whether the package is
	// installed.
	PluginsUnknown bool
}

func (e *ErrNotAvailable) Error() string {
	switch {
	case e.Package == "":
		return fmt.Sprintf("opnsense: resource %s is not in the capability data", e.Resource)
	case e.PluginsUnknown:
		return fmt.Sprintf("opnsense: resource %s needs package %s, but the plugin list is unknown (the API key lacks the firmware privilege)", e.Resource, e.Package)
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
		return fmt.Sprintf("opnsense: %s rejected: %s", e.Resource, transport.Trunc([]byte(e.Body)))
	}
	return fmt.Sprintf("opnsense: %s rejected: %s", e.Resource, joinMap(e.Fields))
}

// FieldDiff is one field that did not read back as written.
type FieldDiff struct {
	Field string
	// Sent and Got are the wire values. They may be secrets (OPNsense marks
	// few password fields as such), so Error() never contains them; show
	// them only where the caller knows the field is not sensitive.
	Sent, Got string
	// Cause names what the capability data knows about this field:
	// "custom-write" (its type converts or normalizes values on write),
	// "custom-save" (the resource is stored through own code that may change
	// or drop values depending on other fields), or "" (nothing: the
	// difference is unexplained). The difference is reported either way.
	Cause string
}

// Causes of a read-back difference (FieldDiff.Cause).
const (
	CauseCustomWrite = capability.GapCustomWrite // the field's type converts values on write
	CauseCustomSave  = capability.GapCustomSave  // the resource is stored through own code
	CauseTransformed = "transformed"             // stored in another form, and came back empty
)

// ErrNotApplied: the firewall answered "saved", but reading the object
// back shows other values. Typical causes: the field does not exist in this
// version after all, or the server normalises the value.
type ErrNotApplied struct {
	Resource, ID string
	Diffs        []FieldDiff
	Hint         string // a likely cause known from the capability data, or ""
}

// Error names the fields and causes, never their values (see FieldDiff).
func (e *ErrNotApplied) Error() string {
	parts := make([]string, 0, len(e.Diffs))
	for _, d := range e.Diffs {
		p := d.Field
		if d.Cause != "" {
			p += " (" + d.Cause + ")"
		}
		parts = append(parts, p)
	}
	id := ""
	if e.ID != "" {
		id = " " + e.ID
	}
	msg := fmt.Sprintf("opnsense: %s%s saved, but these fields read back differently: %s", e.Resource, id, strings.Join(parts, ", "))
	if e.Hint != "" {
		msg += " (" + e.Hint + ")"
	}
	return msg
}

// ErrApply: an apply endpoint did not answer {"status": "ok"}. The
// configuration is saved but maybe not active; the endpoint stays pending.
type ErrApply struct {
	Endpoint string
	Answer   string // at most 300 bytes
}

func (e *ErrApply) Error() string {
	return fmt.Sprintf("opnsense: apply %s did not report ok: %s", e.Endpoint, transport.Trunc([]byte(e.Answer)))
}

// ErrDecode: some fields of an object could not be decoded (an unexpected
// shape). The other fields are returned together with this error, so a
// caller can still use them.
type ErrDecode struct {
	Resource string
	Fields   map[string]string // field -> problem
}

func (e *ErrDecode) Error() string {
	return fmt.Sprintf("opnsense: %s: fields not decoded: %s", e.Resource, joinMap(e.Fields))
}

// ErrSeriesNotInData: the firewall runs a series the capability data does
// not cover; for a newer series (Newer) update the capability data. New
// fails with it: guessing across a series change is not safe.
type ErrSeriesNotInData = capability.ErrSeriesNotInData

// ErrReadOnly: the installed package is older than every version of its
// series in the capability data. The data may describe fields that version
// lacks, so writes are refused; reading works. Update the package, or use
// capability data that covers its version.
// Also returned for every changing call in read-only mode (Config.ReadOnly),
// then with Mode set; errors.Is(err, ErrWriteRefused) is true for those.
type ErrReadOnly struct {
	Resource, Package, Have string
	Reason                  string
	Mode                    bool // refused because of Config.ReadOnly
}

// ErrWriteRefused: a request that could change the firewall was refused in
// read-only mode before it was sent.
var ErrWriteRefused = transport.ErrWriteRefused

// Unwrap makes errors.Is(err, ErrWriteRefused) true in read-only mode.
func (e *ErrReadOnly) Unwrap() error {
	if e.Mode {
		return ErrWriteRefused
	}
	return nil
}

func (e *ErrReadOnly) Error() string {
	return fmt.Sprintf("opnsense: %s: writes refused: %s", e.Resource, e.Reason)
}

// ErrWrongKind: Settings asked for an entry list, or Entries for settings.
type ErrWrongKind struct {
	Resource   string
	Kind, Want string // "settings" or "entries"
}

func (e *ErrWrongKind) Error() string {
	return fmt.Sprintf("opnsense: %s is a %s resource, not %s", e.Resource, e.Kind, e.Want)
}

// ErrNoOperation: the resource has no such operation in this version (for
// example no toggle, or no search).
type ErrNoOperation struct {
	Resource, Operation string
	Package, Have       string
}

func (e *ErrNoOperation) Error() string {
	return fmt.Sprintf("opnsense: %s has no %q operation in %s %s", e.Resource, e.Operation, e.Package, e.Have)
}

// ErrUnexpectedAnswer: the firewall answered a mutation in a way the client
// cannot interpret. The mutation may have taken effect; its apply endpoint
// is marked pending. ID is the entry concerned, if known.
type ErrUnexpectedAnswer struct {
	Resource, Operation, ID string
	// Answer is the raw answer, at most 300 bytes. It may echo values, so
	// Error() leaves it out.
	Answer string
}

func (e *ErrUnexpectedAnswer) Error() string {
	id := ""
	if e.ID != "" {
		id = " " + e.ID
	}
	return fmt.Sprintf("opnsense: %s%s: unexpected answer to %s (raw answer in ErrUnexpectedAnswer.Answer)", e.Resource, id, e.Operation)
}

// ErrStillExists: the firewall answered a delete, but the entry is still
// listed afterwards.
type ErrStillExists struct{ Resource, ID string }

func (e *ErrStillExists) Error() string {
	return fmt.Sprintf("opnsense: %s %s: delete answered, but the entry still exists", e.Resource, e.ID)
}

// ErrIncompleteList: a search returned fewer rows than its total (paged or
// cut); the list cannot be trusted.
type ErrIncompleteList struct {
	Resource   string
	Got, Total int
}

func (e *ErrIncompleteList) Error() string {
	return fmt.Sprintf("opnsense: %s: search returned %d of %d rows", e.Resource, e.Got, e.Total)
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
