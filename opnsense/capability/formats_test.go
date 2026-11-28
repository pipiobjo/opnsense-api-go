// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package capability

import (
	"strings"
	"testing"
)

// TestFormats: each format against the edges where PHP's checks and Go's
// libraries differ. The firewall's own verdicts on such values come from
// the published probes (TestPublishedProbes).
func TestFormats(t *testing.T) {
	comma := &List{Separator: ","}
	cases := []struct {
		name string
		f    ValueFormat
		list *List
		ok   []string
		bad  []string
	}{
		{"network, both families, prefix allowed", ValueFormat{Kind: FormatNetwork, Netmask: "allowed", Any: true}, nil,
			[]string{"192.0.2.10", "2001:db8::10", "192.0.2.0/24", "2001:DB8::/64", " any ", "ANY", "192.0.2.10/24", "::ffff:192.0.2.1"},
			[]string{"192.0.2.256", "192.0.2.010", "fe80::1%em0", "192.0.2.0/33", "2001:db8::/129", "192.0.2.0/+24", "192.0.2.0/", "192.0.2.0/24/1", "contract-test"}},
		{"network, IPv4 only, no prefix, no any", ValueFormat{Kind: FormatNetwork, Family: "ipv4", Netmask: "forbidden"}, nil,
			[]string{"192.0.2.10"}, []string{"2001:db8::10", "192.0.2.0/24", "any"}},
		{"network, prefix required, strict", ValueFormat{Kind: FormatNetwork, Netmask: "required", Strict: true}, nil,
			[]string{"192.0.2.0/24", "2001:db8::/64"}, []string{"192.0.2.10", "192.0.2.10/24", "2001:db8::10/64"}},
		{"network list: any only as the whole value", ValueFormat{Kind: FormatNetwork, Netmask: "allowed", Any: true}, comma,
			[]string{"192.0.2.10,192.0.2.0/24", "any"}, []string{"any,192.0.2.10", "192.0.2.10,x"}},
		{"hostname, default", ValueFormat{Kind: FormatHostname, IP: true}, nil,
			[]string{"ct-1.example.com", "host-", "example.com.", "192.0.2.10", "2001:db8::10", strings.Repeat("a", 63) + ".example"},
			[]string{"_ct.example.com", "-ct.example", "a..b", "ct 1.example.com", "*", "*.example.com", "@", strings.Repeat("a", 64) + ".example"}},
		{"hostname, DNS name, no IP", ValueFormat{Kind: FormatHostname, DNSName: true}, nil,
			[]string{"_ct.example.com", "@"}, []string{"192.0.2.10", "ct/1.example.com", "*.example.com", "ct 1"}},
		{"hostname, wildcards and zone root", ValueFormat{Kind: FormatHostname, HostWildcard: true, DomainWildcard: true, ZoneRoot: true}, nil,
			[]string{"*", "*.example.com", "@", "@.example.com", "*.*"}, []string{"a b", "192.0.2.10"}},
		// HostnameField's loop (upstream): after a valid element a later
		// one fails only in the domain branch (an address where none is
		// allowed, or a DNS name with a space, slash or star)
		{"hostname list", ValueFormat{Kind: FormatHostname}, comma,
			[]string{"a.example,b.example", "a.example,bad host", "a.example,*.x"}, []string{"bad host,a.example", "a.example,192.0.2.1"}},
		{"mac", ValueFormat{Kind: FormatMAC}, nil,
			[]string{"02:00:00:00:00:01", "02-00-00-00-00-0A", "0200.0000.0001"},
			[]string{"02:00:00:00:00", "02:00:00:00:00:00:00:01", "2:0:0:0:0:1", "02:00:00:00:00:0g", "02:00-00:00:00:01"}},
		{"ip-port, both, no host names", ValueFormat{Kind: FormatIPPort}, nil,
			[]string{"192.0.2.10:53", "[2001:db8::10]:53", "192.0.2.10:domain"},
			[]string{"192.0.2.10", "192.0.2.10:0", "192.0.2.10:65536", "192.0.2.10:053", "ct.example.com:53", "192.0.2.10:"}},
		{"ip-port, IPv6, port optional, host names", ValueFormat{Kind: FormatIPPort, Family: "ipv6", PortOptional: true, Hostname: true}, nil,
			[]string{"2001:db8::10", "[2001:db8::10]:53", "ct.example.com:53", "ct.example.com", "192.0.2.10:53"},
			[]string{"[192.0.2.10]:53"}},
		{"url", ValueFormat{Kind: FormatURL}, nil,
			[]string{"https://example.com/contract-test?x=1", "http://192.0.2.10:8080/", "https://[2001:db8::10]/", "ftp://example.com/", "mailto:ct@example.com", "https://u:p@example.com/"},
			[]string{"example.com", "https://", "https://ex ample.com/", "https://-ct.example.com/", "https://example.com/ä", "https://example.com:99999/", "https:example.com"}},
		{"port with services, ranges, aliases", ValueFormat{Kind: FormatPort, Any: true, Services: []string{"http", "https"}, Ranges: true, Aliases: true}, nil,
			[]string{"443", "https", "HTTPS", "any", "1000-2000", "+80-90", "contract_alias"},
			[]string{"0", "65536", "0443", "2000-1000", "0-80", "1000-1000", "1000- 2000", "80,443"}},
		{"port before 26.7: spaces in a range", ValueFormat{Kind: FormatPort, Ranges: true, RangeSpaces: true}, nil,
			[]string{"1000- 2000"}, []string{"http", "contract-test"}},
		{"port list", ValueFormat{Kind: FormatPort, Any: true, Services: []string{"https"}}, comma,
			[]string{"80,443", "https,80"}, []string{"80,0", "HTTPS,80"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, v := range c.ok {
				if err := c.f.check(v, c.list); err != nil {
					t.Errorf("%q: %v, want accepted", v, err)
				}
			}
			for _, v := range c.bad {
				if c.f.check(v, c.list) == nil {
					t.Errorf("%q accepted, want rejected", v)
				}
			}
		})
	}
}

func TestCheckText(t *testing.T) {
	max := int64(3)
	l := &Limits{Pattern: `^[a-z]*$`, MaxLength: &max, Forbidden: " ", PerElement: true}
	comma := &List{Separator: ","}
	for v, want := range map[string]bool{"abc,de": true, "abcd": false, "ab c": false, "ab,C": false} {
		if got := l.checkText(v, comma) == nil; got != want {
			t.Errorf("%q: %v, want %v", v, got, want)
		}
	}
	b := &Limits{Pattern: `^.{1,3}$`, Bytes: true}
	if b.checkText("ää", nil) == nil || b.checkText("äa", nil) != nil {
		t.Error("a byte pattern counts bytes")
	}
}
