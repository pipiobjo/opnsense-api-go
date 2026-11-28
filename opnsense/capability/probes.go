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
	Checked   int      // probes whose verdict the check reached as well
	Skipped   int      // probes on fields without a variant in the tested fragment
	Disagree  []string // probes where the check and the firewall differ
	Resources int      // resources with probes
}

// ReplayProbes runs every published probe (ResVerify.Probes) through the
// value check of the field variant of the tested fragment: a value the
// firewall accepted must pass, one it rejected must fail. The data
// publishes only verdicts about a field's own values: where a rule over
// several fields (model-validation) decided, the probe was written in a
// context of other values that lets the field's values decide, or it is
// not published.
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
					if f == nil {
						out.Skipped += n
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
