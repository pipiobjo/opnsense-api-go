// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package capability

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// CorePackage is the package name of the OPNsense core in the data.
const CorePackage = "opnsense"

// Match says how a package was resolved to a fragment.
type Match int

const (
	// MatchNone: no fragment; operations on the package fail.
	MatchNone Match = iota
	// MatchExact: the combination was seen by the pipeline.
	MatchExact
	// MatchNearest: the package version is known, but not on this core; the
	// fragment of the nearest older core of the series is used.
	MatchNearest
	// MatchAssumed: the version is unknown; the newest fragment of the
	// series is used.
	MatchAssumed
)

func (m Match) String() string {
	if m < MatchNone || m > MatchAssumed {
		return fmt.Sprintf("Match(%d)", int(m))
	}
	return [...]string{"none", "exact", "nearest", "assumed"}[m]
}

// Policy decides what happens with combinations the data has not seen.
type Policy int

const (
	// AssumeNewestInSeries uses the nearest or newest data of the same
	// series. Another hotfix revision of a known release, or a known plugin
	// version from another core of the series, is a note (usual and
	// harmless); a release or plugin version the data has never seen is a
	// warning.
	AssumeNewestInSeries Policy = iota
	// Refuse treats every combination that was not seen as an error.
	Refuse
)

// Resolution is the fragment chosen for one installed package.
type Resolution struct {
	Package  string
	Version  string // installed version
	Fragment string // empty with MatchNone
	Match    Match
	Note     string // MatchNearest: what was used instead
	Warning  string // MatchAssumed or MatchNone: a guess, or nothing
}

// message is the note or the warning, whichever is set.
func (r *Resolution) message() string {
	if r.Warning != "" {
		return r.Warning
	}
	return r.Note
}

// Resolved is the result for one firewall.
type Resolved struct {
	Core      string // core version the firewall reports
	CoreUsed  string // core version of the data that is used
	Release   string
	Series    string
	Framework string
	Packages  map[string]*Resolution // including the core
	Notes     []string               // nearest data of the same release or series; no action needed
	Warnings  []string               // assumptions about versions the data has never seen
}

// Resolve picks the fragment of every installed package for a firewall that
// reports core version core (with hotfix revision, e.g. 26.7.9_1) and the
// given plugin versions.
func (s *Set) Resolve(core string, plugins map[string]string, p Policy) (*Resolved, error) {
	if s == nil || s.Catalog == nil {
		return nil, fmt.Errorf("no capability data")
	}
	r := &Resolved{Core: core, Packages: map[string]*Resolution{}}
	used, c, m, warn := s.resolveCore(core)
	if m == MatchNone {
		return nil, fmt.Errorf("core %s: %s", core, warn)
	}
	if m != MatchExact && p == Refuse {
		return nil, fmt.Errorf("core %s is not in the capability data (%s)", core, warn)
	}
	r.CoreUsed, r.Release, r.Series, r.Framework = used, c.Release, c.Series, c.Framework
	coreRes := &Resolution{Package: CorePackage, Version: core, Match: m}
	switch m {
	case MatchNearest:
		coreRes.Note = warn
		r.Notes = append(r.Notes, warn)
	case MatchAssumed:
		coreRes.Warning = warn
		r.Warnings = append(r.Warnings, warn)
	}
	if d := s.Docs[CorePackage]; d != nil {
		coreRes.Fragment = d.Select[c.Framework][used]
	}
	if coreRes.Fragment == "" {
		return nil, fmt.Errorf("core %s: no fragment for framework %s", used, c.Framework)
	}
	r.Packages[CorePackage] = coreRes

	names := make([]string, 0, len(plugins))
	for n := range plugins {
		names = append(names, n)
	}
	sort.Strings(names)
	var refused []string
	for _, name := range names {
		res := s.resolvePlugin(name, plugins[name], r)
		r.Packages[name] = res
		if res.Note != "" {
			r.Notes = append(r.Notes, res.Note)
		}
		if res.Warning != "" {
			r.Warnings = append(r.Warnings, res.Warning)
		}
		if p == Refuse && (res.Match == MatchNearest || res.Match == MatchAssumed) {
			refused = append(refused, res.message())
		}
	}
	if len(refused) > 0 {
		return nil, fmt.Errorf("not in the capability data: %s", strings.Join(refused, "; "))
	}
	return r, nil
}

func (s *Set) resolveCore(v string) (string, Core, Match, string) {
	cat := s.Catalog
	if c, ok := cat.Cores[v]; ok {
		return v, c, MatchExact, ""
	}
	series, rel := SeriesOf(v), ReleaseOf(v)
	refs := cat.series(series)
	if len(refs) == 0 {
		return "", Core{}, MatchNone, "series " + series + " is not in the capability data"
	}
	pick := func(match func(coreRef) bool) (coreRef, bool) {
		var older, newer *coreRef
		for i := range refs {
			if !match(refs[i]) {
				continue
			}
			if CompareVersions(refs[i].Version, v) <= 0 {
				older = &refs[i] // sorted ascending: the last one is the nearest
			} else if newer == nil {
				newer = &refs[i]
			}
		}
		switch {
		case older != nil:
			return *older, true
		case newer != nil:
			return *newer, true
		}
		return coreRef{}, false
	}
	if c, ok := pick(func(c coreRef) bool { return c.Release == rel }); ok {
		return c.Version, c.Core, MatchNearest,
			fmt.Sprintf("core %s is not in the data; using %s (same release, other hotfix revision)", v, c.Version)
	}
	c, _ := pick(func(coreRef) bool { return true })
	return c.Version, c.Core, MatchAssumed,
		fmt.Sprintf("core %s is not in the data; assuming %s of the same series", v, c.Version)
}

func (s *Set) resolvePlugin(name, version string, r *Resolved) *Resolution {
	res := &Resolution{Package: name, Version: version}
	d := s.Docs[name]
	if d == nil {
		return res // not in the data: no API, or not an official plugin
	}
	// a: seen on this framework
	if h := d.Select[r.Framework][version]; h != "" {
		res.Fragment, res.Match = h, MatchExact
		return res
	}
	// b: seen on other frameworks, always as the same fragment
	byFramework := map[string]string{}
	distinct := map[string]bool{}
	for fw, versions := range d.Select {
		if h := versions[version]; h != "" {
			byFramework[fw] = h
			distinct[h] = true
		}
	}
	if len(distinct) == 1 {
		for h := range distinct {
			res.Fragment, res.Match = h, MatchExact
		}
		return res
	}
	// c: several fragments: the one of the nearest older core of the series
	if len(distinct) > 1 {
		refs := s.Catalog.series(r.Series)
		for i := len(refs) - 1; i >= 0; i-- {
			if CompareVersions(refs[i].Version, r.CoreUsed) > 0 {
				continue
			}
			if h := byFramework[refs[i].Framework]; h != "" {
				res.Fragment, res.Match = h, MatchNearest
				res.Note = fmt.Sprintf("%s %s was not seen on core %s; using its fragment from core %s", name, version, r.CoreUsed, refs[i].Version)
				return res
			}
		}
	}
	// d: unknown version (or only on other series): newest fragment of the series
	best, bestOrder := "", -1
	for h, info := range d.Fragments {
		if info.Order > bestOrder && inSeries(info.Releases, r.Series) {
			best, bestOrder = h, info.Order
		}
	}
	if best != "" {
		res.Fragment, res.Match = best, MatchAssumed
		res.Warning = fmt.Sprintf("%s %s is not in the data; assuming %s (newest of series %s)",
			name, version, strings.Join(d.Fragments[best].Versions, "/"), r.Series)
		return res
	}
	// e
	res.Warning = fmt.Sprintf("%s %s: no data for series %s", name, version, r.Series)
	return res
}

func inSeries(releases []string, series string) bool {
	for _, rel := range releases {
		if SeriesOf(rel) == series {
			return true
		}
	}
	return false
}

// SeriesOf returns the series of a version: 26.7.9_1 -> 26.7.
func SeriesOf(v string) string {
	parts := strings.SplitN(ReleaseOf(v), ".", 3)
	if len(parts) < 2 {
		return v
	}
	return parts[0] + "." + parts[1]
}

// ReleaseOf strips the hotfix revision: 26.7.9_1 -> 26.7.9.
func ReleaseOf(v string) string {
	if i := strings.IndexByte(v, '_'); i >= 0 {
		return v[:i]
	}
	return v
}

// CompareVersions compares package versions such as 26.7.9_1, 1.0_6 or
// 2.1a: release parts numerically (a part's letter suffix after its
// number, "2.1" < "2.1a" < "2.2"), then the hotfix revision. 26.7 < 26.7_1
// < 26.7.1.
func CompareVersions(a, b string) int {
	ra, reva, _ := strings.Cut(a, "_")
	rb, revb, _ := strings.Cut(b, "_")
	pa, pb := strings.Split(ra, "."), strings.Split(rb, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		x, y := "0", "0"
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if c := comparePart(x, y); c != 0 {
			return c
		}
	}
	if reva == "" {
		reva = "0"
	}
	if revb == "" {
		revb = "0"
	}
	return comparePart(reva, revb)
}

// comparePart compares "12" < "12a" < "13" numerically, then by suffix.
func comparePart(a, b string) int {
	na, sa := splitNum(a)
	nb, sb := splitNum(b)
	switch {
	case na < nb:
		return -1
	case na > nb:
		return 1
	}
	return strings.Compare(sa, sb)
}

func splitNum(s string) (int, string) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	n, _ := strconv.Atoi(s[:i]) // empty -> 0
	return n, s[i:]
}
