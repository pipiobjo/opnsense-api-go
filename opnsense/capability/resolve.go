// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package capability

import (
	"errors"
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
	// AssumeNewestInSeries uses the nearest older data of the same
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
	// ReadOnly: the installed version is older than all data of its series,
	// so the data may describe fields it lacks. Reading is allowed, writing
	// is refused.
	ReadOnly bool
}

// ErrSeriesNotInData: the firewall runs a series the capability data does
// not cover. A newer series (Newer) needs newer data; it is not guessed,
// because a series change can change the framework the API is derived from.
type ErrSeriesNotInData struct {
	Core   string // version the firewall reports
	Series string
	Newer  bool   // newer than every series in the data
	Newest string // newest series in the data
}

func (e *ErrSeriesNotInData) Error() string {
	if e.Newer {
		return fmt.Sprintf("core %s: series %s is newer than the capability data (newest %s); update the capability data", e.Core, e.Series, e.Newest)
	}
	return fmt.Sprintf("core %s: series %s is not in the capability data", e.Core, e.Series)
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
		return nil, s.seriesError(core)
	}
	if m != MatchExact && p == Refuse {
		return nil, fmt.Errorf("core %s is not in the capability data (%s)", core, warn)
	}
	r.CoreUsed, r.Release, r.Series, r.Framework = used, c.Release, c.Series, c.Framework
	coreRes := &Resolution{Package: CorePackage, Version: core, Match: m}
	if m == MatchAssumed && CompareVersions(used, core) > 0 {
		// no older core of the series in the data: the newer one may have
		// fields this firewall lacks
		coreRes.ReadOnly = true
		warn = fmt.Sprintf("core %s is older than the capability data of series %s (oldest %s); reading only, writes are refused", core, c.Series, used)
	}
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
		if p == Refuse && (res.Match == MatchNearest || res.Match == MatchAssumed ||
			(res.Match == MatchNone && s.Docs[name] != nil)) {
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
			res.Fragment, res.Match = h, MatchNearest
		}
		res.Note = fmt.Sprintf("%s %s was not seen on core %s; its API was the same on every core it was seen on", name, version, r.CoreUsed)
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
	// d: unknown version: the data of the nearest older known version of
	// the series; older than all of them: the oldest, read-only (newer data
	// may describe fields the installed version lacks)
	type known struct {
		version, hash string
		order         int
	}
	var all []known
	for h, info := range d.Fragments {
		if !inSeries(info.Releases, r.Series) {
			continue
		}
		for _, v := range info.Versions {
			all = append(all, known{v, h, info.Order})
		}
	}
	if len(all) > 0 {
		sort.Slice(all, func(i, j int) bool {
			if c := CompareVersions(all[i].version, all[j].version); c != 0 {
				return c < 0
			}
			return all[i].order < all[j].order
		})
		pick := -1
		for i, k := range all {
			if CompareVersions(k.version, version) <= 0 {
				pick = i
			}
		}
		res.Match = MatchAssumed
		if pick >= 0 {
			res.Fragment = all[pick].hash
			res.Warning = fmt.Sprintf("%s %s is not in the data; assuming %s (nearest older known version of series %s)",
				name, version, all[pick].version, r.Series)
		} else {
			res.Fragment, res.ReadOnly = all[0].hash, true
			res.Warning = fmt.Sprintf("%s %s is older than the capability data of series %s (oldest %s); reading only, writes are refused",
				name, version, r.Series, all[0].version)
		}
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
// < 26.7.1; missing parts count as 0.
//
// The same algorithm, with the same test table, is pkgrepo.CompareVersions
// in opnsense-api-spec; change both together.
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

// ResolveNewerSeries resolves a firewall on a series newer than all data
// (Resolve returned *ErrSeriesNotInData with Newer) against the newest
// core in the data, for reading only: every package is ReadOnly, so writes
// are refused, and a warning says the data is unverified for this series.
// A series change can change the framework the API is derived from, so
// nothing is written on a guess; reading is safe because every answer is
// decoded as data.
func (s *Set) ResolveNewerSeries(core string, plugins map[string]string) (*Resolved, error) {
	var e *ErrSeriesNotInData
	if err := s.seriesError(core); !errors.As(err, &e) || !e.Newer {
		return nil, fmt.Errorf("core %s: not on a series newer than the capability data", core)
	}
	newest := ""
	for v, c := range s.Catalog.Cores {
		if c.Series == e.Newest && (newest == "" || CompareVersions(v, newest) > 0) {
			newest = v
		}
	}
	r, err := s.Resolve(newest, plugins, AssumeNewestInSeries)
	if err != nil {
		return nil, err
	}
	r.Core = core
	warn := fmt.Sprintf("core %s: series %s is newer than the capability data (newest %s); reading with the data of %s, unverified for this series; writes are refused until the capability data covers %s",
		core, e.Series, e.Newest, newest, e.Series)
	for _, res := range r.Packages {
		res.ReadOnly = true
	}
	r.Packages[CorePackage].Warning = warn
	r.Warnings = append([]string{warn}, r.Warnings...)
	return r, nil
}

// seriesError: the core's series is not in the data; says whether it is
// newer than all of it.
func (s *Set) seriesError(core string) error {
	series := SeriesOf(core)
	newest := ""
	for _, c := range s.Catalog.Cores {
		if newest == "" || CompareVersions(c.Series, newest) > 0 {
			newest = c.Series
		}
	}
	return &ErrSeriesNotInData{Core: core, Series: series, Newest: newest,
		Newer: newest != "" && CompareVersions(series, newest) > 0}
}
