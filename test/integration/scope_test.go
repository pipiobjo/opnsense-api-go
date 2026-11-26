// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package integration

// Which packages a run tests. Locally, the integration tests can run on
// several VMs at once (tools/parallel.sh), each with a group of plugins
// installed; OPNSENSE_PACKAGES then names the packages this VM tests
// ("opnsense" for the core, which exactly one VM tests). Resources and
// tests of other packages are left to the other VMs: they do not run here
// (no skip, see TestMain), and the per-series floor is checked on the
// merged result (TestMergedGroups). No build tag: the unit run checks the
// rules below.

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// needs: the tests that need particular packages, and which. A test not
// listed needs only what every VM has, or reads what is installed. A test
// that needs a package without being listed fails in a run whose scope
// lacks it (missing), so a forgotten entry is loud, not silent.
var needs = map[string][]string{
	"TestOSPFNeighborCycle":     {"os-frr"},
	"TestSettingsSetAndRestore": {"os-frr"},
	"TestRecordedBehaviour":     {"os-frr"},
	"TestListFieldsKeepOrder":   {"opnsense"}, // a firewall alias and a Kea subnet
}

// scope is the set of packages a run tests; nil: all of them.
type scope map[string]bool

// scopeFrom reads OPNSENSE_PACKAGES (comma-separated; empty: all).
func scopeFrom(v string) scope {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	s := scope{}
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			s[p] = true
		}
	}
	return s
}

func currentScope() scope { return scopeFrom(os.Getenv("OPNSENSE_PACKAGES")) }

// has: the run tests this package.
func (s scope) has(pkg string) bool { return s == nil || s[pkg] }

// skipPattern: the go test -skip pattern for the tests whose packages are
// outside the scope, and the extra tests ("" when there is none).
func skipPattern(s scope, extra ...string) string {
	out := slices.Clone(extra)
	for name, pkgs := range needs {
		for _, p := range pkgs {
			if !s.has(p) {
				out = append(out, name)
				break
			}
		}
	}
	if len(out) == 0 {
		return ""
	}
	slices.Sort(out)
	return "^(" + strings.Join(out, "|") + ")$"
}

// groupSummary is what TestEveryVerifiedResource of one VM reports for the
// merge (OPNSENSE_SUMMARY): the counts of its final log line and the
// resources it tested.
type groupSummary struct {
	Series   string         `json:"series"`
	Packages []string       `json:"packages"`
	Counts   map[string]int `json:"counts"`
	Tested   []string       `json:"tested"`
}

// mergeSummaries adds the summaries of one series' VMs: the counts add up;
// a resource tested on two VMs, a package in two scopes, or summaries of
// different series are an error (the groups overlapped).
func mergeSummaries(parts []groupSummary) (groupSummary, error) {
	out := groupSummary{Counts: map[string]int{}}
	pkgAt, resAt := map[string]int{}, map[string]int{}
	for i, p := range parts {
		if i == 0 {
			out.Series = p.Series
		} else if p.Series != out.Series {
			return out, fmt.Errorf("summary %d is of series %s, summary 1 of %s", i+1, p.Series, out.Series)
		}
		for _, pk := range p.Packages {
			if j, ok := pkgAt[pk]; ok {
				return out, fmt.Errorf("package %s was tested by summary %d and %d", pk, j+1, i+1)
			}
			pkgAt[pk] = i
			out.Packages = append(out.Packages, pk)
		}
		for _, id := range p.Tested {
			if j, ok := resAt[id]; ok {
				return out, fmt.Errorf("resource %s was tested by summary %d and %d", id, j+1, i+1)
			}
			resAt[id] = i
			out.Tested = append(out.Tested, id)
		}
		for k, v := range p.Counts {
			out.Counts[k] += v
		}
	}
	slices.Sort(out.Packages)
	slices.Sort(out.Tested)
	if out.Counts["tested"] != len(out.Tested) {
		return out, fmt.Errorf("the summaries count %d tested resources but list %d", out.Counts["tested"], len(out.Tested))
	}
	return out, nil
}

func readSummaries(files []string) ([]groupSummary, error) {
	var out []groupSummary
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var s groupSummary
		if err := json.Unmarshal(b, &s); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		out = append(out, s)
	}
	return out, nil
}

// Claim (testing.md): a run scoped to some packages leaves out exactly the
// tests that need another package, every test named in needs exists, and
// the summaries of one series' VMs add up only when no package and no
// resource was tested twice.
func TestScope(t *testing.T) {
	if s := scopeFrom(" "); s != nil || !s.has("os-x") || skipPattern(s) != "" {
		t.Errorf("no scope must test everything: %v %q", s, skipPattern(s))
	}
	frr := scopeFrom("os-frr, os-haproxy")
	if got := skipPattern(frr, "TestMergedGroups"); got != "^(TestListFieldsKeepOrder|TestMergedGroups)$" {
		t.Errorf("scope os-frr: skip %q", got)
	}
	core := scopeFrom("opnsense,os-acme-client")
	if got := skipPattern(core); got != "^(TestOSPFNeighborCycle|TestRecordedBehaviour|TestSettingsSetAndRestore)$" {
		t.Errorf("scope core: skip %q", got)
	}
	if core.has("os-frr") || !core.has("opnsense") {
		t.Errorf("has: %v", core)
	}
	// every test needs names is a test of this package
	src := ""
	files, _ := os.ReadDir(".")
	for _, f := range files {
		if strings.HasSuffix(f.Name(), "_test.go") {
			b, _ := os.ReadFile(f.Name())
			src += string(b)
		}
	}
	for name := range needs {
		if !regexp.MustCompile(`(?m)^func ` + name + `\(t \*testing\.T\)`).MatchString(src) {
			t.Errorf("needs names %s, which is no test here", name)
		}
	}

	a := groupSummary{Series: "26.7", Packages: []string{"opnsense", "os-a"}, Counts: map[string]int{"tested": 2, "skipped": 1}, Tested: []string{"x", "y"}}
	b := groupSummary{Series: "26.7", Packages: []string{"os-b"}, Counts: map[string]int{"tested": 1}, Tested: []string{"z"}}
	m, err := mergeSummaries([]groupSummary{b, a})
	if err != nil || m.Counts["tested"] != 3 || m.Counts["skipped"] != 1 || strings.Join(m.Packages, ",") != "opnsense,os-a,os-b" {
		t.Errorf("merge: %+v %v", m, err)
	}
	for name, bad := range map[string]groupSummary{
		"package twice":  {Series: "26.7", Packages: []string{"os-a"}, Counts: map[string]int{}},
		"resource twice": {Series: "26.7", Packages: []string{"os-c"}, Counts: map[string]int{"tested": 1}, Tested: []string{"y"}},
		"other series":   {Series: "26.1", Packages: []string{"os-c"}, Counts: map[string]int{}},
		"count and list": {Series: "26.7", Packages: []string{"os-c"}, Counts: map[string]int{"tested": 2}, Tested: []string{"w"}},
	} {
		if _, err := mergeSummaries([]groupSummary{a, b, bad}); err == nil {
			t.Errorf("%s: merged without an error", name)
		}
	}
}
