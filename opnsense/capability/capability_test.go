// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package capability

import (
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

func TestResolveReal(t *testing.T) {
	s := loadReal(t)
	cases := []struct {
		name        string
		core, frr   string
		coreUsed    string
		coreMatch   Match
		frrMatch    Match
		frrFragment string
		warn, note  string
	}{
		{"exact", "26.7.9_1", "2.1", "26.7.9_1", MatchExact, MatchExact, "b04bde19061e2dec", "", ""},
		// usual after an update: a note, not a warning
		{"other hotfix revision of a known release", "26.7.9", "2.1", "26.7.9_1", MatchNearest, MatchExact, "b04bde19061e2dec", "", "same release, other hotfix revision"},
		{"newer release of a known series", "26.7.10", "2.1", "26.7.9_1", MatchAssumed, MatchExact, "b04bde19061e2dec", "assuming 26.7.9_1", ""},
		// seen only on other cores (same API everywhere): a note, not "exact"
		{"same plugin version, other framework, same fragment", "26.7.9_1", "1.55", "26.7.9_1", MatchExact, MatchNearest, "1debf887d1d01f6e", "", "its API was the same on every core"},
		{"unknown plugin version", "26.7.9_1", "9.9", "26.7.9_1", MatchExact, MatchAssumed, "b04bde19061e2dec", "os-frr 9.9 is not in the data", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := s.Resolve(c.core, map[string]string{"os-frr": c.frr, "os-theme-vicuna": "1.0"}, AssumeNewestInSeries)
			if err != nil {
				t.Fatal(err)
			}
			if r.CoreUsed != c.coreUsed || r.Packages[CorePackage].Match != c.coreMatch {
				t.Errorf("core: used %s match %s", r.CoreUsed, r.Packages[CorePackage].Match)
			}
			f := r.Packages["os-frr"]
			if f.Match != c.frrMatch || f.Fragment != c.frrFragment {
				t.Errorf("os-frr: %s %s", f.Match, f.Fragment)
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
	if _, err := s.Resolve("26.7.9_1", map[string]string{"os-frr": "2.1"}, Refuse); err != nil {
		t.Errorf("exact must pass with Refuse: %v", err)
	}
	if _, err := s.Resolve("26.7.9", nil, Refuse); err == nil {
		t.Error("Refuse must fail for an unknown core revision")
	}
	if _, err := s.Resolve("26.7.9_1", map[string]string{"os-frr": "9.9"}, Refuse); err == nil {
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

func TestCompareVersions(t *testing.T) {
	ordered := []string{"1.0", "1.0_6", "1.1", "25.7", "25.7_1", "25.7.1", "25.7.9", "25.7.10", "25.7.11_9", "26.1"}
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
	if SeriesOf("26.7.9_1") != "26.7" || ReleaseOf("26.7.9_1") != "26.7.9" || SeriesOf("26.1") != "26.1" {
		t.Error("SeriesOf/ReleaseOf")
	}
}

func TestRealDataFieldsAndVariants(t *testing.T) {
	s := loadReal(t)
	r := s.Docs["os-frr"].Resources["quagga/ospfsettings#networks.network"]
	// OSPF area: free text in 1.x, a relation to an area entry in 2.x
	old := r.FieldFor("area", "70ea32d17d684e96") // 1.45
	cur := r.FieldFor("area", "b04bde19061e2dec") // 2.1
	if old == nil || cur == nil || old.Type != "TextField" || cur.Type != "ModelRelationField" || cur.ReadShape != "select" {
		t.Fatalf("area variants: %+v / %+v", old, cur)
	}
	if a := r.APIFor("b04bde19061e2dec"); a == nil || a.Operations["get"].Wrapper != "network" {
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
	if _, err := (&Set{}).Resolve("26.7.9_1", nil, AssumeNewestInSeries); err == nil {
		t.Error("Resolve without catalog must fail, not panic")
	}
}

func TestVersionsWithLetters(t *testing.T) {
	ordered := []string{"2.1", "2.1a", "2.1b", "2.2", "26.1.b", "26.1.1"}
	for i := 0; i+1 < len(ordered); i++ {
		if CompareVersions(ordered[i], ordered[i+1]) >= 0 || CompareVersions(ordered[i+1], ordered[i]) <= 0 {
			t.Errorf("%s < %s expected", ordered[i], ordered[i+1])
		}
	}
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
