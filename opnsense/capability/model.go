// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

// Package capability reads the OPNsense capability data (format 1, see
// https://github.com/pipiobjo/opnsense-api-spec/blob/main/docs/capabilities.md),
// resolves which fragment of each package applies to a firewall, and checks
// values against it before anything is sent.
//
// The package has no network access and no dependency on the client; other
// tools can use it on its own.
package capability

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"slices"
	"sort"
	"strings"
	"sync"
)

// Format is the capability data format this package reads.
const Format = 1

// Set is a loaded catalog with all package documents.
type Set struct {
	Catalog *Catalog
	Docs    map[string]*Doc // package name -> document ("opnsense" is the core)
}

// Catalog is catalog.json.
type Catalog struct {
	Format    int    `json:"format"`
	Generator string `json:"generator"`
	// DataID identifies the data state (opnsense-api-spec
	// docs/capabilities.md, "Identity and releases"); empty in data built
	// before it existed.
	DataID   string              `json:"data_id,omitempty"`
	Cores    map[string]Core     `json:"cores"`
	Releases []Release           `json:"releases"`
	Packages map[string]PkgEntry `json:"packages"`
	once     sync.Once
	coresBy  map[string][]coreRef // series -> cores sorted by version, see series()
}

// Core maps a core package version to its release and framework.
type Core struct {
	Release   string `json:"release"`
	Series    string `json:"series"`
	Framework string `json:"framework"`
}

type coreRef struct {
	Version string
	Core
}

// Release is one OPNsense release with its catalog states.
type Release struct {
	Release      string        `json:"release"`
	Series       string        `json:"series"`
	Status       string        `json:"status"`
	Current      string        `json:"current"`
	Compositions []Composition `json:"compositions"`
}

// Composition is one catalog state of a release.
type Composition struct {
	ID        string            `json:"id"`
	Generator string            `json:"generator"`
	Core      string            `json:"core"`
	Framework string            `json:"framework"`
	Fragments map[string]string `json:"fragments"`
	Verified  *Verification     `json:"verified,omitempty"`
}

// Verification is the contract test run of a composition.
type Verification struct {
	Date      string         `json:"date"`
	Generator string         `json:"generator"`
	Instance  string         `json:"instance"`
	Packages  []string       `json:"packages"`
	Results   map[string]int `json:"results"`
}

// PkgEntry lists a package document.
type PkgEntry struct {
	File      string   `json:"file"`
	Fragments []string `json:"fragments"`
}

// Doc is the capability document of one package.
type Doc struct {
	Format    int                          `json:"format"`
	Package   string                       `json:"package"`
	Generator string                       `json:"generator"`
	Fragments map[string]FragmentInfo      `json:"fragments"`
	Select    map[string]map[string]string `json:"select"` // framework -> version -> fragment
	Resources map[string]*Resource         `json:"resources"`
	Actions   map[string][]*Action         `json:"actions,omitempty"`
}

// FragmentInfo says where a fragment was seen.
type FragmentInfo struct {
	Versions []string `json:"versions"`
	Cores    []string `json:"cores"`
	Releases []string `json:"releases"`
	Order    int      `json:"order"`
}

// Resource is a settings model or an entry list.
type Resource struct {
	Kind string `json:"kind"` // settings, entries
	// Family: one of several resources on the same model path, told apart
	// by their own add and search endpoints (bind primary, secondary and
	// forward domains); the identifier ends in "@<family>".
	Family     string                `json:"family,omitempty"`
	In         []string              `json:"in"`
	API        []*API                `json:"api"`
	Fields     map[string][]*Field   `json:"fields"`
	Verified   map[string]*ResVerify `json:"verified,omitempty"`
	SharedWith []string              `json:"shared_with,omitempty"`
}

// API is how a resource is addressed in some fragments.
type API struct {
	In         In                    `json:"in"`
	Model      string                `json:"model"`
	ModelPath  string                `json:"model_path,omitempty"`
	Wrapper    string                `json:"wrapper,omitempty"`
	Apply      string                `json:"apply,omitempty"`
	Operations map[string]*Operation `json:"operations"`
	// Gaps of the stored data as a whole; "custom-save": the model saves
	// through its own code, or the entries are converted on the way, so
	// values may be changed or dropped depending on other fields.
	Gaps []string `json:"gaps,omitempty"`
}

// CustomSave reports whether the firewall stores this resource through
// its own code (gap custom-save).
func (a *API) CustomSave() bool { return a != nil && slices.Contains(a.Gaps, GapCustomSave) }

// Gap codes of the capability data that change what the client does. The
// spec repository defines all codes (internal/gap, docs/concepts.md);
// codes not listed here are carried in the data but do not change
// behaviour.
const (
	GapCustomSave        = "custom-save"         // stored or loaded through own code: read-back may differ
	GapCustomWrite       = "custom-write"        // the field type converts values on write
	GapCustomReadShape   = "custom-read-shape"   // the field type renders its value with own code on read
	GapOverlayUnknown    = "overlay-unknown"     // the endpoint overwrites fields it does not declare
	GapResultNotReturned = "result-not-returned" // the endpoint answers nothing; the existence check decides
)

// HasGap reports whether the operation carries the gap code.
func (o *Operation) HasGap(code string) bool { return o != nil && slices.Contains(o.Gaps, code) }

// Operation is one endpoint of a resource.
type Operation struct {
	Path    string   `json:"path"`
	Methods []string `json:"methods"`
	Params  []string `json:"params,omitempty"`
	Wrapper string   `json:"wrapper,omitempty"`
	Outer   string   `json:"outer,omitempty"`
	// Forced: fields this endpoint sets to a fixed value; Computed: fields
	// it fills itself. Values sent for them are overwritten.
	Forced   map[string]string `json:"forced,omitempty"`
	Computed []string          `json:"computed,omitempty"`
	// Transformed: writable fields stored in another form than sent (for
	// example base64-encoded); they read back differently.
	Transformed []string `json:"transformed,omitempty"`
	Source      string   `json:"source"`
	Gaps        []string `json:"gaps,omitempty"`
}

// Transforms reports whether the endpoint stores the field in another form.
func (o *Operation) Transforms(field string) bool {
	for _, t := range o.Transformed {
		if t == field {
			return true
		}
	}
	return false
}

// Overwrites reports whether the endpoint overwrites the field, and how.
func (o *Operation) Overwrites(field string) (string, bool) {
	if v, ok := o.Forced[field]; ok {
		return fmt.Sprintf("forced to %q by %s", v, o.Path), true
	}
	for _, c := range o.Computed {
		if c == field {
			return "computed by " + o.Path, true
		}
	}
	return "", false
}

// Field is one variant of a field.
type Field struct {
	In        In     `json:"in"`
	Type      string `json:"type"`
	Base      string `json:"base,omitempty"`
	ReadShape string `json:"read_shape,omitempty"`
	Multiple  bool   `json:"multiple,omitempty"`
	Required  bool   `json:"required,omitempty"`
	Volatile  bool   `json:"volatile,omitempty"`
	// ServerSet: the firewall fills the field itself and ignores a value
	// sent (unique ids, auto numbers, audit fields); WriteOnly: stored but
	// never returned (passwords). Both come from the data, so the client
	// keeps no list of field types.
	ServerSet   bool              `json:"server_set,omitempty"`
	WriteOnly   bool              `json:"write_only,omitempty"`
	Default     *string           `json:"default,omitempty"`
	Options     []Option          `json:"options,omitempty"`
	Relations   []Relation        `json:"relations,omitempty"`
	Constraints map[string]string `json:"constraints,omitempty"`
	Gaps        []string          `json:"gaps,omitempty"`
}

// Option is a static option of a field.
type Option struct {
	Value string `json:"value"`
	Label string `json:"label,omitempty"`
	Group string `json:"group,omitempty"`
}

// Relation names the entry list a relation field points to.
type Relation struct {
	Source string `json:"source"`
	Items  string `json:"items"`
}

// Action is an endpoint that is not a resource operation.
type Action struct {
	In      []string `json:"in"`
	Kind    string   `json:"kind"`
	Methods []string `json:"methods"`
	Params  []string `json:"params,omitempty"`
	Model   string   `json:"model,omitempty"`
	Source  string   `json:"source"`
	Gaps    []string `json:"gaps,omitempty"`
}

// ResVerify is the contract test result of a resource in one fragment.
type ResVerify struct {
	Release     string `json:"release"`
	Composition string `json:"composition"`
	Generator   string `json:"generator"`
	Date        string `json:"date"`
	Read        Status `json:"read,omitempty"`
	Write       Status `json:"write,omitempty"`
	// Steps: what was done; see the Step constants.
	Steps           []string       `json:"steps,omitempty"`
	Sample          map[string]any `json:"sample,omitempty"`
	Generated       []string       `json:"generated,omitempty"`
	RuntimeRequired []string       `json:"runtime_required,omitempty"`
	Findings        []string       `json:"findings,omitempty"`
	// SameDefinitionAs: this fragment was not tested itself; the result is
	// that of the named fragment of the same series, whose api and field
	// variants are identical. Empty: tested itself.
	SameDefinitionAs string `json:"same_definition_as,omitempty"`
	// ReturnedBySearch: write-only fields whose stored value the search
	// answer contained in this run.
	ReturnedBySearch []string `json:"returned_by_search,omitempty"`
}

// Status is a result of the contract test (ResVerify.Read and Write); the
// spec repository defines the vocabulary (internal/verify, status.go).
type Status string

// Results of the contract test. Only StatusOK is a pass.
const (
	StatusOK       Status = "ok"
	StatusAccepted Status = "accepted"  // a failure declared expected upstream (verify/accepted.json)
	StatusSkipped  Status = "skipped"   // not tested; the findings say why
	StatusKnownGap Status = "known-gap" // differs where the data already marks a gap
	StatusMismatch Status = "mismatch"
	StatusError    Status = "error"
)

// Steps of a write test (ResVerify.Steps) that change what a result means.
const (
	// StepReadBackRestore: a settings write changed a field to another
	// value, read it back, restored it and read it back again (generator
	// 0.10.0 and later). Without it, a settings "ok" only wrote the current
	// value back, which an endpoint that stores nothing also passes.
	StepReadBackRestore = "read-back-restore"
)

// In is "*" (every fragment of the resource) or a list of fragments.
type In struct {
	All    bool
	Hashes []string
}

// UnmarshalJSON reads "*" or a list of hashes.
func (in *In) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		if s != "*" {
			return fmt.Errorf("in: %q is neither \"*\" nor a list", s)
		}
		in.All = true
		return nil
	}
	return json.Unmarshal(b, &in.Hashes)
}

// MarshalJSON writes "*" or the list.
func (in In) MarshalJSON() ([]byte, error) {
	if in.All {
		return []byte(`"*"`), nil
	}
	return json.Marshal(in.Hashes)
}

// Has reports whether fragment h is covered.
func (in In) Has(h string) bool {
	if in.All {
		return true
	}
	for _, x := range in.Hashes {
		if x == h {
			return true
		}
	}
	return false
}

// Available reports whether the resource exists in fragment h.
func (r *Resource) Available(h string) bool {
	for _, x := range r.In {
		if x == h {
			return true
		}
	}
	return false
}

// APIFor returns the API variant of fragment h, or nil.
func (r *Resource) APIFor(h string) *API {
	if !r.Available(h) {
		return nil
	}
	for _, a := range r.API {
		if a.In.Has(h) {
			return a
		}
	}
	return nil
}

// FieldFor returns the variant of a field in fragment h, or nil.
func (r *Resource) FieldFor(name, h string) *Field {
	if !r.Available(h) {
		return nil
	}
	for _, f := range r.Fields[name] {
		if f.In.Has(h) {
			return f
		}
	}
	return nil
}

// Clone returns a deep copy, so a caller can change it without changing the
// data the client works with.
func (f *Field) Clone() *Field {
	if f == nil {
		return nil
	}
	c := *f
	c.In = In{All: f.In.All, Hashes: slices.Clone(f.In.Hashes)}
	if f.Default != nil {
		d := *f.Default
		c.Default = &d
	}
	c.Options = slices.Clone(f.Options)
	c.Relations = slices.Clone(f.Relations)
	c.Gaps = slices.Clone(f.Gaps)
	if f.Constraints != nil {
		c.Constraints = make(map[string]string, len(f.Constraints))
		for k, v := range f.Constraints {
			c.Constraints[k] = v
		}
	}
	return &c
}

// FieldsFor returns all fields that exist in fragment h.
func (r *Resource) FieldsFor(h string) map[string]*Field {
	out := map[string]*Field{}
	for name := range r.Fields {
		if f := r.FieldFor(name, h); f != nil {
			out[name] = f
		}
	}
	return out
}

// MaxFile is the largest data file Load reads (the core document is about
// 2 MB).
const MaxFile = 64 << 20

// MaxPackages and MaxTotal bound a whole load (today: 75 packages, about
// 4 MB): a crafted catalog cannot make Load read without end.
const (
	MaxPackages = 1000
	MaxTotal    = 512 << 20
)

// Load reads catalog.json and capabilities/<package>.json from fsys (for
// example os.DirFS of an unpacked catalog release) and checks the result.
// The directory is trusted input: os.DirFS follows symbolic links.
func Load(fsys fs.FS) (*Set, error) {
	raw, err := readFile(fsys, "catalog.json")
	if err != nil {
		return nil, err
	}
	cat, err := ParseCatalog(raw)
	if err != nil {
		return nil, err
	}
	if len(cat.Packages) > MaxPackages {
		return nil, fmt.Errorf("catalog: %d packages, more than %d", len(cat.Packages), MaxPackages)
	}
	s := &Set{Catalog: cat, Docs: map[string]*Doc{}}
	total := len(raw)
	names := make([]string, 0, len(cat.Packages))
	for name := range cat.Packages {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		file := path.Clean(cat.Packages[name].File)
		if !fs.ValidPath(file) || file == "." || strings.HasPrefix(file, "../") {
			return nil, fmt.Errorf("catalog: bad file name for %s: %q", name, cat.Packages[name].File)
		}
		b, err := readFile(fsys, file)
		if err != nil {
			return nil, err
		}
		if total += len(b); total > MaxTotal {
			return nil, fmt.Errorf("catalog: data larger than %d bytes in total", MaxTotal)
		}
		d, err := ParseDoc(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		if d.Package != name {
			return nil, fmt.Errorf("%s: document is for %q, catalog says %q", file, d.Package, name)
		}
		s.Docs[name] = d
	}
	return s, s.Check()
}

func readFile(fsys fs.FS, name string) ([]byte, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxFile {
		return nil, fmt.Errorf("%s: larger than %d bytes", name, MaxFile)
	}
	return b, nil
}

// ParseCatalog decodes catalog.json and refuses an unknown format.
func ParseCatalog(b []byte) (*Catalog, error) {
	var c Catalog
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("catalog: %w", err)
	}
	if c.Format != Format {
		return nil, fmt.Errorf("catalog: format %d, this client reads format %d", c.Format, Format)
	}
	return &c, nil
}

// ParseDoc decodes a package document and refuses an unknown format.
func ParseDoc(b []byte) (*Doc, error) {
	var d Doc
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	if d.Format != Format {
		return nil, fmt.Errorf("format %d, this client reads format %d", d.Format, Format)
	}
	return &d, nil
}

// series returns the cores of a series sorted by version; the index is
// built once, on first use (safe for concurrent use).
func (c *Catalog) series(name string) []coreRef {
	c.once.Do(func() {
		c.coresBy = map[string][]coreRef{}
		for v, core := range c.Cores {
			c.coresBy[core.Series] = append(c.coresBy[core.Series], coreRef{v, core})
		}
		for s := range c.coresBy {
			refs := c.coresBy[s]
			sort.Slice(refs, func(i, j int) bool { return CompareVersions(refs[i].Version, refs[j].Version) < 0 })
		}
	})
	return c.coresBy[name]
}

// Check verifies the structure and the references inside the set, so that
// nothing later has to guard against missing parts: a catalog and a core
// document exist; every selection, resource and variant names known
// fragments; every fragment of a resource is covered by exactly one API
// variant; operations have /api/ paths; no entry is null.
func (s *Set) Check() error {
	if s == nil || s.Catalog == nil {
		return errors.New("capability: no catalog")
	}
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	for v, c := range s.Catalog.Cores {
		if c.Framework == "" || c.Series == "" {
			add("catalog: core %s lacks framework or series", v)
		}
	}
	if s.Docs[CorePackage] == nil {
		add("capability: no document for the core (%s)", CorePackage)
	}
	for name, d := range s.Docs {
		if d == nil {
			add("%s: null document", name)
			continue
		}
		for fw, byVersion := range d.Select {
			for v, h := range byVersion {
				if _, ok := d.Fragments[h]; !ok {
					add("%s: select[%s][%s] names unknown fragment %s", name, fw, v, h)
				}
			}
		}
		for id, r := range d.Resources {
			if r == nil {
				add("%s %s: null resource", name, id)
				continue
			}
			if r.Kind != "settings" && r.Kind != "entries" {
				add("%s %s: unknown kind %q", name, id, r.Kind)
			}
			for i, a := range r.API {
				if a == nil {
					add("%s %s: null api variant %d", name, id, i)
					continue
				}
				for op, o := range a.Operations {
					if o == nil || !strings.HasPrefix(o.Path, "/api/") {
						add("%s %s: operation %s has no /api/ path", name, id, op)
					}
				}
			}
			for f, variants := range r.Fields {
				for i, v := range variants {
					if v == nil {
						add("%s %s: null variant %d of field %s", name, id, i, f)
					}
				}
			}
			for _, h := range r.In {
				if _, ok := d.Fragments[h]; !ok {
					add("%s %s: unknown fragment %s", name, id, h)
				}
				n := 0
				for _, a := range r.API {
					if a != nil && a.In.Has(h) {
						n++
					}
				}
				if n != 1 {
					add("%s %s: fragment %s has %d API variants", name, id, h, n)
				}
			}
		}
	}
	return errors.Join(errs...)
}
