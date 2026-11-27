// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package capability

import (
	"fmt"
	"maps"
	"slices"
)

// ProbeReplay is the outcome of running the published field probes
// through the client's value check (Field.Encode, which Entries.Check and
// Settings.Check use for every value).
type ProbeReplay struct {
	Checked     int      // probes whose verdict the check reached as well
	Skipped     int      // probes on fields whose verdict depends on other fields (model-validation) or that have no variant
	Disagree    []string // probes where the check and the firewall differ
	Resources   int      // resources with probes
	ModelChecks int      // fields with model-validation, not replayed
}

// ReplayProbes runs every published probe (ResVerify.Probes) through the
// value check of the field variant of the tested fragment: a value the
// firewall accepted must pass, one it rejected must fail. Fields with the
// gap model-validation are not replayed: the firewall's verdict there
// depends on other fields, which a check of one value cannot know.
func (s *Set) ReplayProbes() ProbeReplay {
	var out ProbeReplay
	for _, pkg := range slices.Sorted(maps.Keys(s.Docs)) {
		d := s.Docs[pkg]
		for _, id := range slices.Sorted(maps.Keys(d.Resources)) {
			r := d.Resources[id]
			counted := false
			for _, hash := range slices.Sorted(maps.Keys(r.Verified)) {
				v := r.Verified[hash]
				if len(v.Probes) == 0 || v.SameDefinitionAs != "" {
					continue // a carried result names the same values again
				}
				if !counted {
					out.Resources++
					counted = true
				}
				for _, name := range slices.Sorted(maps.Keys(v.Probes)) {
					vd := v.Probes[name]
					f := r.FieldFor(name, hash)
					n := len(vd.Accepted) + len(vd.Rejected)
					if f == nil || slices.Contains(f.Gaps, GapModelValidation) {
						out.Skipped += n
						if f != nil {
							out.ModelChecks++
						}
						continue
					}
					for _, val := range vd.Accepted {
						if _, err := f.Encode(val); err != nil {
							out.Disagree = append(out.Disagree, fmt.Sprintf("%s %s %s=%q: the firewall accepted it, the check says: %v", pkg, id, name, val, err))
						} else {
							out.Checked++
						}
					}
					for _, val := range vd.Rejected {
						if _, err := f.Encode(val); err == nil {
							out.Disagree = append(out.Disagree, fmt.Sprintf("%s %s %s=%q: the firewall rejected it, the check lets it pass", pkg, id, name, val))
						} else {
							out.Checked++
						}
					}
				}
			}
		}
	}
	return out
}
