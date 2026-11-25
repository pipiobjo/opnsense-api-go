// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package capability

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing"
	"testing/fstest"
)

// testdata/catalog: the real catalog.json of 34 releases, the real os-frr
// document reduced to the OSPF resources, the core document without
// resources.
func loadReal(t *testing.T) *Set {
	t.Helper()
	s, err := Load(os.DirFS("testdata/catalog"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// fragFor: the fragment the raw data selects for a package version on a
// core (read from Select, not through the resolver under test). Tests name
// versions, never hashes: a generator change changes every hash.
func fragFor(t testing.TB, s *Set, core, pkg, version string) string {
	t.Helper()
	c, ok := s.Catalog.Cores[core]
	if !ok {
		t.Fatalf("core %s not in the test data", core)
	}
	h := s.Docs[pkg].Select[c.Framework][version]
	if h == "" {
		t.Fatalf("%s %s not seen on core %s in the test data", pkg, version, core)
	}
	return h
}

// newestCore: the newest core of a series in the data.
func newestCore(s *Set, series string) string {
	newest := ""
	for v, c := range s.Catalog.Cores {
		if c.Series == series && (newest == "" || CompareVersions(v, newest) > 0) {
			newest = v
		}
	}
	return newest
}

// versionOf: the package versions of a fragment, for checks that only care
// which version's data was chosen.
func versionsOf(s *Set, pkg, frag string) string {
	return strings.Join(s.Docs[pkg].Fragments[frag].Versions, ",")
}

func TestResolveReal(t *testing.T) {
	s := loadReal(t)
	newest := newestCore(s, "26.7")
	exact := fragFor(t, s, "26.7.9_3", "os-frr", "2.1")
	cases := []struct {
		name       string
		core, frr  string
		coreUsed   string
		coreMatch  Match
		frrMatch   Match
		frrVersion string // the data of this os-frr version is used
		frrExact   string // and, where it matters, exactly this fragment
		warn, note string
	}{
		{"exact", "26.7.9_3", "2.1", "26.7.9_3", MatchExact, MatchExact, "2.1", exact, "", ""},
		// usual after an update: a note, not a warning
		{"other hotfix revision of a known release", "26.7.9", "2.1", "26.7.9_3", MatchNearest, MatchExact, "2.1", exact, "", "same release, other hotfix revision"},
		{"newer release of a known series", "26.7.99", "2.1", newest, MatchAssumed, MatchExact, "2.1", fragFor(t, s, newest, "os-frr", "2.1"), "assuming " + newest, ""},
		// seen only on other cores (same API everywhere): a note, not "exact"
		{"same plugin version, other framework, same fragment", "26.7.9_3", "1.55", "26.7.9_3", MatchExact, MatchNearest, "1.55", "", "", "its API was the same on every core"},
		// unknown: the nearest older known version's data
		{"unknown plugin version", "26.7.9_3", "9.9", "26.7.9_3", MatchExact, MatchAssumed, "2.1", "", "os-frr 9.9 is not in the data", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := s.Resolve(c.core, map[string]string{"os-frr": c.frr, "os-theme-vicuna": "1.0"}, AssumeNewestInSeries)
			if err != nil {
				t.Fatal(err)
			}
			if r.CoreUsed != c.coreUsed || r.Packages[CorePackage].Match != c.coreMatch {
				t.Errorf("core: used %s match %s, want %s %s", r.CoreUsed, r.Packages[CorePackage].Match, c.coreUsed, c.coreMatch)
			}
			f := r.Packages["os-frr"]
			if f.Match != c.frrMatch || !strings.Contains(","+versionsOf(s, "os-frr", f.Fragment)+",", ","+c.frrVersion+",") ||
				(c.frrExact != "" && f.Fragment != c.frrExact) {
				t.Errorf("os-frr: %s %s (versions %s), want %s data of %s %s", f.Match, f.Fragment, versionsOf(s, "os-frr", f.Fragment), c.frrMatch, c.frrVersion, c.frrExact)
			}
			if c.warn == "" && len(r.Warnings) > 0 {
				t.Errorf("unexpected warnings: %v", r.Warnings)
			}
			if c.warn != "" && !strings.Contains(strings.Join(r.Warnings, "|"), c.warn) {
				t.Errorf("warnings %v lack %q", r.Warnings, c.warn)
			}
			if c.note == "" && len(r.Notes) > 0 {
				t.Errorf("unexpected notes: %v", r.Notes)
			}
			if c.note != "" && !strings.Contains(strings.Join(r.Notes, "|"), c.note) {
				t.Errorf("notes %v lack %q", r.Notes, c.note)
			}
			if th := r.Packages["os-theme-vicuna"]; th.Match != MatchNone || th.Warning != "" {
				t.Errorf("a package without data is none, silently: %+v", th)
			}
		})
	}
}

func TestResolveRefuse(t *testing.T) {
	s := loadReal(t)
	if _, err := s.Resolve("26.7.9_3", map[string]string{"os-frr": "2.1"}, Refuse); err != nil {
		t.Errorf("exact must pass with Refuse: %v", err)
	}
	if _, err := s.Resolve("26.7.9", nil, Refuse); err == nil {
		t.Error("Refuse must fail for an unknown core revision")
	}
	if _, err := s.Resolve("26.7.9_3", map[string]string{"os-frr": "9.9"}, Refuse); err == nil {
		t.Error("Refuse must fail for an unknown plugin version")
	}
	if _, err := s.Resolve("27.1", nil, AssumeNewestInSeries); err == nil || !strings.Contains(err.Error(), "series 27.1") {
		t.Errorf("an unknown series must fail: %v", err)
	}
}

// Case c of the resolver: one plugin version with different fragments on
// different frameworks of the same series (os-web-proxy-sso 2.2_3 in 26.1).
func TestResolveNearestOlderCore(t *testing.T) {
	s := &Set{Catalog: &Catalog{Format: 1, Cores: map[string]Core{
		"26.1.1": {Release: "26.1.1", Series: "26.1", Framework: "f1"},
		"26.1.2": {Release: "26.1.2", Series: "26.1", Framework: "f2"},
		"26.1.3": {Release: "26.1.3", Series: "26.1", Framework: "f3"},
		"26.1.4": {Release: "26.1.4", Series: "26.1", Framework: "f4"},
	}}, Docs: map[string]*Doc{
		CorePackage: {Select: map[string]map[string]string{"f1": {"26.1.1": "c1"}, "f2": {"26.1.2": "c2"}, "f3": {"26.1.3": "c3"}, "f4": {"26.1.4": "c4"}},
			Fragments: map[string]FragmentInfo{"c1": {}, "c2": {}, "c3": {}, "c4": {}}},
		"os-x": {Select: map[string]map[string]string{"f1": {"2.2_3": "x1"}, "f3": {"2.2_3": "x3"}},
			Fragments: map[string]FragmentInfo{"x1": {Releases: []string{"26.1.1"}}, "x3": {Releases: []string{"26.1.3"}}}},
	}}
	r, err := s.Resolve("26.1.4", map[string]string{"os-x": "2.2_3"}, AssumeNewestInSeries)
	if err != nil {
		t.Fatal(err)
	}
	if x := r.Packages["os-x"]; x.Match != MatchNearest || x.Fragment != "x3" {
		t.Errorf("want the fragment of the nearest older core (26.1.3): %+v", x)
	}
	if len(r.Warnings) != 0 || len(r.Notes) != 1 || r.Packages["os-x"].Note == "" {
		t.Errorf("a known plugin version from another core is a note: notes %q, warnings %q", r.Notes, r.Warnings)
	}
	// on 26.1.2 the version exists on an older (26.1.1) and a newer core
	// (26.1.3): the older one counts
	r, err = s.Resolve("26.1.2", map[string]string{"os-x": "2.2_3"}, AssumeNewestInSeries)
	if err != nil {
		t.Fatal(err)
	}
	if x := r.Packages["os-x"]; x.Match != MatchNearest || x.Fragment != "x1" {
		t.Errorf("want the fragment of the nearest older core (26.1.1), not a newer one: %+v", x)
	}
	if _, err := s.Resolve("26.1.4", map[string]string{"os-x": "2.2_3"}, Refuse); err == nil {
		t.Error("Refuse must fail for case c")
	}
}

// The core is never resolved to newer data when older data of the same
// release or series exists (newer data may describe fields the firewall
// lacks): between two releases the older one is assumed, between two
// hotfix revisions of the release the older revision is the nearest.
func TestResolveCoreNeverNewer(t *testing.T) {
	set := func(cores ...string) *Set {
		s := &Set{Catalog: &Catalog{Format: 1, Cores: map[string]Core{}}, Docs: map[string]*Doc{
			CorePackage: {Select: map[string]map[string]string{}, Fragments: map[string]FragmentInfo{}}}}
		for i, v := range cores {
			fw, frag := fmt.Sprintf("f%d", i), fmt.Sprintf("c%d", i)
			s.Catalog.Cores[v] = Core{Release: ReleaseOf(v), Series: SeriesOf(v), Framework: fw}
			s.Docs[CorePackage].Select[fw] = map[string]string{v: frag}
			s.Docs[CorePackage].Fragments[frag] = FragmentInfo{}
		}
		return s
	}
	for _, c := range []struct {
		data      []string
		firewall  string
		used      string
		match     Match
		writeable bool
	}{
		{[]string{"26.1.1", "26.1.3"}, "26.1.2", "26.1.1", MatchAssumed, true},
		{[]string{"26.1.2", "26.1.2_3"}, "26.1.2_1", "26.1.2", MatchNearest, true},
		{[]string{"26.1.2_1", "26.1.2_3", "26.1.4"}, "26.1.2_2", "26.1.2_1", MatchNearest, true},
	} {
		r, err := set(c.data...).Resolve(c.firewall, nil, AssumeNewestInSeries)
		if err != nil {
			t.Fatalf("%s with data %v: %v", c.firewall, c.data, err)
		}
		core := r.Packages[CorePackage]
		if r.CoreUsed != c.used || core.Match != c.match || core.ReadOnly == c.writeable {
			t.Errorf("%s with data %v: used %s (%s, read-only %v), want %s (%s)", c.firewall, c.data, r.CoreUsed, core.Match, core.ReadOnly, c.used, c.match)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	// the version-order table opnsense-api-spec publishes (version-order.json,
	// copied by tools/testdata.sh); the spec's own comparison is tested
	// against the same file, so both implementations must agree
	raw, err := os.ReadFile("testdata/catalog/version-order.json")
	if err != nil {
		t.Fatal(err)
	}
	var table struct {
		Ordered []string    `json:"ordered"`
		Equal   [][2]string `json:"equal"`
	}
	if err := json.Unmarshal(raw, &table); err != nil || len(table.Ordered) < 2 || len(table.Equal) == 0 {
		t.Fatalf("version-order.json: %v (%d ordered, %d equal)", err, len(table.Ordered), len(table.Equal))
	}
	ordered := table.Ordered
	for i := 0; i < len(ordered); i++ {
		for j := 0; j < len(ordered); j++ {
			got := CompareVersions(ordered[i], ordered[j])
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got != want {
				t.Errorf("CompareVersions(%s, %s) = %d, want %d", ordered[i], ordered[j], got, want)
			}
		}
	}
	for _, eq := range table.Equal {
		if CompareVersions(eq[0], eq[1]) != 0 || CompareVersions(eq[1], eq[0]) != 0 {
			t.Errorf("CompareVersions(%s, %s) must be 0 both ways", eq[0], eq[1])
		}
	}
	if SeriesOf("26.7.9_3") != "26.7" || ReleaseOf("26.7.9_3") != "26.7.9" || SeriesOf("26.1") != "26.1" {
		t.Error("SeriesOf/ReleaseOf")
	}
}

func TestRealDataFieldsAndVariants(t *testing.T) {
	s := loadReal(t)
	r := s.Docs["os-frr"].Resources["quagga/ospfsettings#networks.network"]
	// OSPF area: free text in 1.x, a relation to an area entry in 2.x
	var v145 string
	for h, info := range s.Docs["os-frr"].Fragments {
		for _, v := range info.Versions {
			if v == "1.45" {
				v145 = h
			}
		}
	}
	v21 := fragFor(t, s, "26.7.9_3", "os-frr", "2.1")
	old := r.FieldFor("area", v145)
	cur := r.FieldFor("area", v21)
	if old == nil || cur == nil || old.Type != "TextField" || cur.Type != "ModelRelationField" || cur.ReadShape != "select" {
		t.Fatalf("area variants: %+v / %+v", old, cur)
	}
	if a := r.APIFor(v21); a == nil || a.Operations["get"].Wrapper != "network" {
		t.Errorf("operation wrapper: %+v", a)
	}
	if r.FieldFor("area", "0000000000000000") != nil {
		t.Error("unknown fragment must give no field")
	}
}

func TestLoadRefusesOtherFormat(t *testing.T) {
	if _, err := ParseCatalog([]byte(`{"format":2}`)); err == nil || !strings.Contains(err.Error(), "format 2") {
		t.Errorf("format 2 must be refused: %v", err)
	}
	if _, err := ParseDoc([]byte(`{"format":2,"package":"x"}`)); err == nil {
		t.Error("document format 2 must be refused")
	}
}

func TestCheckFindsBrokenReferences(t *testing.T) {
	s := &Set{Catalog: &Catalog{Format: 1}, Docs: map[string]*Doc{"os-x": {
		Fragments: map[string]FragmentInfo{"a": {}},
		Select:    map[string]map[string]string{"f": {"1.0": "b"}},
		Resources: map[string]*Resource{"x/y": {Kind: "settings", In: []string{"a"}, API: []*API{}}},
	}}}
	err := s.Check()
	if err == nil || !strings.Contains(err.Error(), "unknown fragment b") || !strings.Contains(err.Error(), "0 API variants") {
		t.Errorf("Check: %v", err)
	}
}

func TestCheckNullEntriesWithoutPanic(t *testing.T) {
	core := &Doc{Fragments: map[string]FragmentInfo{}}
	cases := map[string]*Set{
		"no catalog":     {},
		"null document":  {Catalog: &Catalog{}, Docs: map[string]*Doc{CorePackage: core, "os-x": nil}},
		"null resource":  {Catalog: &Catalog{}, Docs: map[string]*Doc{CorePackage: core, "os-x": {Resources: map[string]*Resource{"a/b": nil}}}},
		"null api":       {Catalog: &Catalog{}, Docs: map[string]*Doc{CorePackage: core, "os-x": {Resources: map[string]*Resource{"a/b": {Kind: "settings", API: []*API{nil}}}}}},
		"null field":     {Catalog: &Catalog{}, Docs: map[string]*Doc{CorePackage: core, "os-x": {Resources: map[string]*Resource{"a/b": {Kind: "settings", Fields: map[string][]*Field{"f": {nil}}}}}}},
		"null operation": {Catalog: &Catalog{}, Docs: map[string]*Doc{CorePackage: core, "os-x": {Resources: map[string]*Resource{"a/b": {Kind: "settings", API: []*API{{Operations: map[string]*Operation{"get": nil}}}}}}}},
		"no core doc":    {Catalog: &Catalog{}, Docs: map[string]*Doc{}},
		"bad kind":       {Catalog: &Catalog{}, Docs: map[string]*Doc{CorePackage: core, "os-x": {Resources: map[string]*Resource{"a/b": {Kind: "other"}}}}},
	}
	for name, s := range cases {
		if err := s.Check(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	var nilSet *Set
	if err := nilSet.Check(); err == nil {
		t.Error("nil set accepted")
	}
	if _, err := (&Set{}).Resolve("26.7.9_3", nil, AssumeNewestInSeries); err == nil {
		t.Error("Resolve without catalog must fail, not panic")
	}
}

func TestVersionsWithLetters(t *testing.T) {
	// their order is in version-order.json (TestCompareVersions)
	if CompareVersions("2.1a", "2.1") == 0 {
		t.Error("a letter suffix is a different version")
	}
	if Match(9).String() != "Match(9)" || Kind(-1).String() != "Kind(-1)" {
		t.Error("out-of-range String")
	}
}

func TestLoadRefusesEscapingFileNames(t *testing.T) {
	for _, file := range []string{"../x.json", "/etc/passwd", "", "capabilities/../../x"} {
		cat := `{"format":1,"cores":{},"releases":[],"packages":{"opnsense":{"file":"` + file + `","fragments":[]}}}`
		fsys := fstest.MapFS{"catalog.json": {Data: []byte(cat)}}
		if _, err := Load(fsys); err == nil || !strings.Contains(err.Error(), "bad file name") {
			t.Errorf("file %q: %v", file, err)
		}
	}
}

//go:embed testdata/catalog
var embeddedCatalog embed.FS

// Claim (ADR 0003): data embedded with go:embed loads through fs.Sub, the
// way a provider ships it.
func TestLoadFromEmbed(t *testing.T) {
	sub, err := fs.Sub(embeddedCatalog, "testdata/catalog")
	if err != nil {
		t.Fatal(err)
	}
	s, err := Load(sub)
	if err != nil {
		t.Fatal(err)
	}
	if s.Catalog.DataID == "" || s.Docs[CorePackage] == nil {
		t.Errorf("embedded data: data_id %q, %d documents", s.Catalog.DataID, len(s.Docs))
	}
}
