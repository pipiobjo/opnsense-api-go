// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package integration

// The tolerance files of the integration test and how a series finds its
// rules. No build tag: the unit run checks the files and the rules, so a
// broken entry fails before a VM is booted.

import (
	"encoding/json"
	"maps"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/pipiobjo/opnsense-api-go/opnsense/capability"
)

// testedFloor is the minimum tested count of a series (tested-floor.txt:
// lines "<series> <count>"). A series without a line (a new one) gets the
// floor of the newest older series that has one: a new series has at
// least the resources of the one before, and a data or plugin loss must
// not pass unnoticed there. An older series without a line fails.
func testedFloor(t *testing.T, series string) int {
	t.Helper()
	b, err := os.ReadFile("tested-floor.txt")
	if err != nil {
		t.Fatal(err)
	}
	floors := map[string]int{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		n, err := strconv.Atoi(f[len(f)-1])
		if len(f) != 2 || err != nil {
			t.Fatalf("tested-floor.txt: %q", line)
		}
		floors[f[0]] = n
	}
	from, ok := seriesFor(series, slices.Collect(maps.Keys(floors)))
	if !ok {
		t.Fatalf("tested-floor.txt has no floor for series %s or an older one", series)
	}
	if from != series {
		t.Logf("tested-floor.txt has no line for series %s: using the floor of %s (%d)", series, from, floors[from])
	}
	return floors[from]
}

// seriesFor: the series itself if listed, else the newest listed series
// older than it (a new series inherits the rules of the one before).
func seriesFor(series string, listed []string) (string, bool) {
	best := ""
	for _, s := range listed {
		if s == series {
			return s, true
		}
		if capability.CompareVersions(s, series) < 0 && (best == "" || capability.CompareVersions(s, best) > 0) {
			best = s
		}
	}
	return best, best != ""
}

// applyFailure is an entry of apply-failures.json: an apply endpoint that
// cannot work on the isolated VM, the series it fails on, why, and a text
// its error answer must contain (only that failure is tolerated).
type applyFailure struct {
	Series []string `json:"series"`
	Reason string   `json:"reason"`
	Match  string   `json:"match"`
}

// applyFailures: the entries that apply to a series. A series no entry
// names (a new one) takes the entries of the newest older series named in
// the file, so the VM's known limits do not turn a new series red.
func applyFailures(t *testing.T, series string) map[string]applyFailure {
	t.Helper()
	b, err := os.ReadFile("apply-failures.json")
	if err != nil {
		t.Fatal(err)
	}
	var list map[string]applyFailure
	if err := json.Unmarshal(b, &list); err != nil {
		t.Fatalf("apply-failures.json: %v", err)
	}
	all := map[string]bool{}
	for p, e := range list {
		if !strings.HasPrefix(p, "/api/") || e.Reason == "" || e.Match == "" || len(e.Series) == 0 {
			t.Fatalf("apply-failures.json: %s needs an /api/ path, series, a reason and a match", p)
		}
		for _, s := range e.Series {
			all[s] = true
		}
	}
	use, ok := seriesFor(series, slices.Collect(maps.Keys(all)))
	out := map[string]applyFailure{}
	if !ok {
		return out
	}
	if use != series {
		t.Logf("apply-failures.json names no series %s: using the entries of %s", series, use)
	}
	for p, e := range list {
		if slices.Contains(e.Series, use) {
			out[p] = e
		}
	}
	return out
}

// Claim (testing.md): the tolerance files are well formed (every
// apply-failures.json entry has a match), and a series without its own
// line or entries, such as a new one, takes those of the newest older
// series instead of none.
func TestToleranceFiles(t *testing.T) {
	for _, c := range []struct {
		series string
		listed []string
		want   string
		ok     bool
	}{
		{"26.7", []string{"25.7", "26.1", "26.7"}, "26.7", true},
		{"27.1", []string{"25.7", "26.1", "26.7"}, "26.7", true},
		{"26.4", []string{"25.7", "26.1", "26.7"}, "26.1", true},
		{"25.1", []string{"25.7", "26.1"}, "", false},
		{"26.10", []string{"26.7", "26.1"}, "26.7", true},
	} {
		if got, ok := seriesFor(c.series, c.listed); got != c.want || ok != c.ok {
			t.Errorf("seriesFor(%s, %v) = %q %v, want %q %v", c.series, c.listed, got, ok, c.want, c.ok)
		}
	}
	newest := applyFailures(t, "26.7")
	if len(newest) == 0 {
		t.Fatal("no apply-failures.json entries for 26.7")
	}
	if next := applyFailures(t, "27.1"); !reflect.DeepEqual(next, newest) {
		t.Errorf("a new series must take the entries of the newest one: %v", next)
	}
	if testedFloor(t, "27.1") != testedFloor(t, "26.7") || testedFloor(t, "26.7") == 0 {
		t.Error("a new series must take the floor of the newest one")
	}
}
