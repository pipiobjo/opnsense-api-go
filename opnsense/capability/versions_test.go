// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package capability

import (
	"errors"
	"strings"
	"testing"
)

// series 26.1 with cores 26.1.1 to 26.1.4; os-x known in 1.0 (on 26.1.1)
// and 3.0 (on 26.1.3), os-y known only on 25.7.
func versionData() *Set {
	return &Set{Catalog: &Catalog{Format: 1, Cores: map[string]Core{
		"25.7.1": {Release: "25.7.1", Series: "25.7", Framework: "g1"},
		"26.1.1": {Release: "26.1.1", Series: "26.1", Framework: "f1"},
		"26.1.2": {Release: "26.1.2", Series: "26.1", Framework: "f2"},
		"26.1.3": {Release: "26.1.3", Series: "26.1", Framework: "f3"},
		"26.1.4": {Release: "26.1.4", Series: "26.1", Framework: "f4"},
	}}, Docs: map[string]*Doc{
		CorePackage: {Select: map[string]map[string]string{"g1": {"25.7.1": "c0"}, "f1": {"26.1.1": "c1"}, "f2": {"26.1.2": "c2"}, "f3": {"26.1.3": "c3"}, "f4": {"26.1.4": "c4"}},
			Fragments: map[string]FragmentInfo{"c0": {}, "c1": {}, "c2": {}, "c3": {}, "c4": {}}},
		"os-x": {Select: map[string]map[string]string{"f1": {"1.0": "x1"}, "f3": {"3.0": "x3"}},
			Fragments: map[string]FragmentInfo{"x1": {Versions: []string{"1.0"}, Releases: []string{"26.1.1"}, Order: 1},
				"x3": {Versions: []string{"3.0"}, Releases: []string{"26.1.3"}, Order: 2}}},
		"os-y": {Select: map[string]map[string]string{"g1": {"1.0": "y1"}},
			Fragments: map[string]FragmentInfo{"y1": {Versions: []string{"1.0"}, Releases: []string{"25.7.1"}, Order: 1}}},
	}}
}

// A firewall on a series the data does not have (27.1, newer than all):
// a typed error that says to update the data, not a guess across a series.
func TestResolveNewerSeriesIsTypedError(t *testing.T) {
	_, err := versionData().Resolve("27.1", nil, AssumeNewestInSeries)
	var e *ErrSeriesNotInData
	if !errors.As(err, &e) || !e.Newer || e.Series != "27.1" || e.Newest != "26.1" {
		t.Fatalf("want ErrSeriesNotInData{Newer, 27.1, newest 26.1}, got %#v (%v)", e, err)
	}
	if !strings.Contains(err.Error(), "update the capability data") {
		t.Errorf("message must say what to do: %v", err)
	}
	_, err = versionData().Resolve("24.7.3", nil, AssumeNewestInSeries)
	if !errors.As(err, &e) || e.Newer {
		t.Errorf("an older series is not in the data either, but not newer: %#v (%v)", e, err)
	}
}

// An unknown plugin version between two known ones uses the nearest older
// known version, never newer data.
func TestResolvePluginBetweenKnownVersions(t *testing.T) {
	r, err := versionData().Resolve("26.1.4", map[string]string{"os-x": "2.0"}, AssumeNewestInSeries)
	if err != nil {
		t.Fatal(err)
	}
	if x := r.Packages["os-x"]; x.Fragment != "x1" || x.Match != MatchAssumed || x.ReadOnly {
		t.Errorf("want the data of 1.0 (nearest older), assumed, writable: %+v", x)
	}
}

// A plugin older than every known version of the series: the oldest data
// is used for reading, writes are refused (the data may describe fields
// the installed version lacks).
func TestResolvePluginOlderThanData(t *testing.T) {
	r, err := versionData().Resolve("26.1.4", map[string]string{"os-x": "0.5"}, AssumeNewestInSeries)
	if err != nil {
		t.Fatal(err)
	}
	x := r.Packages["os-x"]
	if x.Fragment != "x1" || !x.ReadOnly || !strings.Contains(x.Warning, "older than") {
		t.Errorf("want the oldest data, read-only, with a warning: %+v", x)
	}
}

// A core older than every core of its series in the data: read-only too.
func TestResolveCoreOlderThanData(t *testing.T) {
	d := versionData()
	delete(d.Catalog.Cores, "26.1.1")
	r, err := d.Resolve("26.1.0", nil, AssumeNewestInSeries)
	if err != nil {
		t.Fatal(err)
	}
	if c := r.Packages[CorePackage]; !c.ReadOnly || !strings.Contains(c.Warning, "older than") {
		t.Errorf("core older than the data must be read-only: %+v", c)
	}
	r, err = d.Resolve("26.1.3", nil, AssumeNewestInSeries)
	if err != nil || r.Packages[CorePackage].ReadOnly {
		t.Errorf("a known core is writable: %+v %v", r.Packages[CorePackage], err)
	}
}

// Refuse also refuses a package the data has, but not for this series.
func TestRefuseCoversPackageWithoutSeriesData(t *testing.T) {
	_, err := versionData().Resolve("26.1.3", map[string]string{"os-y": "1.0"}, Refuse)
	if err == nil {
		t.Error("Refuse must fail for os-y, which has data only for 25.7")
	}
	if _, err := versionData().Resolve("26.1.3", map[string]string{"os-unknown": "1.0"}, Refuse); err != nil {
		t.Errorf("a package without any data (no API) is not refused: %v", err)
	}
}

// A plugin version seen only on other cores is labelled honestly: a note,
// not "exact".
func TestResolveOtherCoresOnlyIsANote(t *testing.T) {
	r, err := versionData().Resolve("26.1.4", map[string]string{"os-x": "3.0"}, AssumeNewestInSeries)
	if err != nil {
		t.Fatal(err)
	}
	if x := r.Packages["os-x"]; x.Fragment != "x3" || x.Match == MatchExact || x.Note == "" {
		t.Errorf("want x3 with a note, not exact: %+v", x)
	}
}
