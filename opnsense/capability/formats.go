// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package capability

// The formats of the capability data (its docs/capabilities.md, section
// Formats). Each check follows the PHP code the data derived the format
// from, including PHP's filter functions; the published field probes are
// replayed through them (ReplayProbes), so a difference to the firewall
// shows up as a failing test.

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// format kinds
const (
	FormatNetwork  = "network"
	FormatHostname = "hostname"
	FormatMAC      = "mac"
	FormatIPPort   = "ip-port"
	FormatURL      = "url"
	FormatPort     = "port"
)

// check judges a non-empty wire value.
func (f *ValueFormat) check(s string, list *List) error {
	switch f.Kind {
	case FormatNetwork:
		return f.network(s, list)
	case FormatHostname:
		return f.hostname(s, list)
	case FormatMAC:
		for _, e := range elements(strings.TrimSpace(s), list) {
			if !phpMAC(e) {
				return fmt.Errorf("%q is not a MAC address", e)
			}
		}
	case FormatIPPort:
		for _, e := range elements(strings.TrimSpace(s), list) {
			if !f.ipPort(e) {
				return fmt.Errorf("%q is not an address and port", e)
			}
		}
	case FormatURL:
		if !phpURL(s) {
			return errors.New("not a URL")
		}
	case FormatPort:
		return f.port(s, list)
	}
	return nil // a kind this version does not know: the firewall decides
}

// elements: the list elements (BaseSetField::iterateInput), or the value.
func elements(s string, list *List) []string {
	if list == nil {
		return []string{s}
	}
	return strings.Split(s, list.Separator)
}

// network: NetworkField. The firewall stores the value trimmed and in
// lower case and checks that.
func (f *ValueFormat) network(s string, list *List) error {
	s = strings.ToLower(strings.TrimSpace(s))
	if f.Any && s == "any" {
		return nil
	}
	for _, e := range elements(s, list) {
		addr := e
		if strings.Contains(e, "/") {
			if f.Netmask == "forbidden" {
				return fmt.Errorf("%q: no prefix length allowed", e)
			}
			parts := strings.Split(e, "/")
			if len(parts) > 2 || !ctypeDigit(parts[1]) {
				return fmt.Errorf("%q: not an address with a prefix length", e)
			}
			max := int64(32)
			if strings.Contains(parts[0], ":") {
				max = 128
			}
			if n, err := strconv.ParseInt(parts[1], 10, 64); err != nil || n > max {
				return fmt.Errorf("%q: prefix length over %d", e, max)
			}
			if f.Strict && !subnetStrict(parts[0], parts[1]) {
				return fmt.Errorf("%q: address bits set after the prefix length", e)
			}
			addr = parts[0]
		} else if f.Netmask == "required" {
			return fmt.Errorf("%q: a prefix length is required", e)
		}
		if !phpIP(addr, f.Family != "ipv6", f.Family != "ipv4") {
			return fmt.Errorf("%q: not an %s address", addr, familyName(f.Family))
		}
	}
	return nil
}

func familyName(f string) string {
	switch f {
	case "ipv4":
		return "IPv4"
	case "ipv6":
		return "IPv6"
	}
	return "IP"
}

// subnetStrict: Util::isSubnetStrict, no address bits after the prefix.
func subnetStrict(addr, bits string) bool {
	a, err := netip.ParseAddr(addr)
	if err != nil || a.Zone() != "" {
		return false
	}
	n, _ := strconv.Atoi(bits)
	p, err := a.Prefix(n)
	return err == nil && p.Addr() == a
}

// hostTrouble: the characters HostnameField refuses in a DNS name
// (preg_match('/(\s|\/|\*)/'); PCRE's \s includes the vertical tab)
const hostTrouble = " \t\n\v\f\r/*"

// hostname: HostnameField, its loop as written: once an element passed,
// $result stays true for later ones unless they reach the domain branch.
func (f *ValueFormat) hostname(s string, list *List) error {
	result := false
	for _, e := range elements(strings.TrimSpace(s), list) {
		v := e
		isIP := phpIP(v, true, true)
		if f.DomainWildcard && strings.HasPrefix(v, "*.") {
			v = v[2:]
		} else if f.ZoneRoot && strings.HasPrefix(v, "@.") {
			v = v[2:]
		}
		switch {
		case f.ZoneRoot && v == "@", f.HostWildcard && v == "*", f.IP && isIP:
			result = true
		case phpDomain(v, !f.DNSName):
			result = !isIP && !strings.ContainsAny(v, hostTrouble)
		}
		if !result {
			return fmt.Errorf("%q is not a valid host name", e)
		}
	}
	return nil
}

// ipPort: IPPortField.
func (f *ValueFormat) ipPort(v string) bool {
	parts := strings.Split(v, ":")
	if f.Family == "ipv4" || f.Family == "" {
		if len(parts) == 2 && phpIP(parts[0], true, false) && phpPort(parts[1]) {
			return true
		}
		if f.PortOptional && phpIP(v, true, false) {
			return true
		}
	}
	if f.Hostname {
		if len(parts) == 2 && phpPort(parts[1]) && phpDomain(parts[0], true) {
			return true
		}
		if f.PortOptional && phpDomain(v, true) {
			return true
		}
	}
	if f.Family == "ipv6" || f.Family == "" {
		ps := bracketSplit(v)
		if len(ps) == 2 && phpIP(ps[0], false, true) && strings.Contains(ps[1], ":") && phpPort(strings.Trim(ps[1], ": ")) {
			return true
		}
		if f.PortOptional && phpIP(v, false, true) {
			return true
		}
	}
	return false
}

// bracketSplit: preg_split('/\[([^\]]+)\]/', v, -1,
// PREG_SPLIT_DELIM_CAPTURE | PREG_SPLIT_NO_EMPTY).
func bracketSplit(v string) []string {
	var out []string
	for _, m := range bracketRe.FindAllStringSubmatchIndex(v, -1) {
		if pre := v[:m[0]]; pre != "" {
			out = append(out, pre)
		}
		out = append(out, v[m[2]:m[3]])
		v = v[m[1]:]
		break // later brackets stay in the rest: one is enough for two parts
	}
	if v != "" {
		out = append(out, v)
	}
	return out
}

var bracketRe = regexp.MustCompile(`\[([^\]]+)\]`)

// aliasRe: what may be the name of an alias
var aliasRe = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// serviceRe: what may be a name of the firewall's services database
// (/etc/services), which the data cannot list: such a port is the
// firewall's to judge
var serviceRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._+-]*$`)

// phpPort: Util::isPort for one port, a number 1-65535 as
// FILTER_VALIDATE_INT reads it (digits only, no leading zero) or a service
// name.
func phpPort(p string) bool {
	if serviceRe.MatchString(p) {
		return true
	}
	return ctypeDigit(p) && phpIntIn(p, 1, 65535)
}

// port: PortField. A single value is stored trimmed and in lower case when
// that is "any" or a service name.
func (f *ValueFormat) port(s string, list *List) error {
	for _, e := range elements(s, list) {
		if list == nil {
			e = portName(f, e)
		}
		switch {
		case f.Any && e == "any", containsString(f.Services, e), decimalPort(e):
		case f.Ranges && rangeShaped(e) && f.portRange(e):
		case f.Aliases && aliasRe.MatchString(e) && !ctypeDigit(e):
			// a port alias: the firewall knows its aliases
		default:
			return fmt.Errorf("%q is not a port the field takes", e)
		}
	}
	return nil
}

func portName(f *ValueFormat, e string) string {
	t := strings.ToLower(strings.TrimSpace(e))
	if (f.Any && t == "any") || containsString(f.Services, t) {
		return t
	}
	return e
}

// decimalPort: one of the options "1" to "65535" as PHP writes numbers.
func decimalPort(e string) bool {
	return ctypeDigit(e) && (e == "0" || e[0] != '0') && phpIntIn(e, 1, 65535)
}

func rangeShaped(e string) bool { return strings.Count(e, "-") == 1 }

// portRange: "a-b" with a < b, each FILTER_VALIDATE_INT in 1..65535; spaces
// around a number only where the format says so.
func (f *ValueFormat) portRange(e string) bool {
	a, b, _ := strings.Cut(e, "-")
	if !f.RangeSpaces && (a != strings.TrimSpace(a) || b != strings.TrimSpace(b)) {
		return false
	}
	x, okA := phpInt(phpTrim(a))
	y, okB := phpInt(phpTrim(b))
	return okA && okB && x >= 1 && x <= 65535 && y >= 1 && y <= 65535 && x < y
}

// phpTrim: what FILTER_VALIDATE_INT trims.
func phpTrim(s string) string { return strings.Trim(s, " \t\r\v\n\x00") }

// phpInt: FILTER_VALIDATE_INT without options: an optional sign, digits,
// no leading zero.
func phpInt(s string) (int64, bool) {
	d := strings.TrimLeft(s, "+-")
	if len(s)-len(d) > 1 || d == "" || !ctypeDigit(d) || len(d) > 1 && d[0] == '0' {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil
}

func phpIntIn(s string, min, max int64) bool {
	n, ok := phpInt(s)
	return ok && n >= min && n <= max
}

func ctypeDigit(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func containsString(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// phpIP: filter_var FILTER_VALIDATE_IP with the given families: no zone
// index, no leading zeros in IPv4.
func phpIP(s string, v4, v6 bool) bool {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return false
	}
	if strings.Contains(s, ":") {
		return v6
	}
	return v4 && a.Is4()
}

// phpDomain: FILTER_VALIDATE_DOMAIN (ext/filter, _php_filter_validate_domain);
// hostname: FILTER_FLAG_HOSTNAME.
func phpDomain(d string, hostname bool) bool {
	l, e := len(d), len(d)
	if l > 0 && d[l-1] == '.' {
		e, l = l-1, l-1
	}
	if l > 253 {
		return false
	}
	at := func(i int) byte {
		if i < len(d) {
			return d[i]
		}
		return 0
	}
	if at(0) == '.' || hostname && !alnum(at(0)) {
		return false
	}
	label := 1
	for s := 0; s < e; s++ {
		c := d[s]
		if c == '.' {
			if at(s+1) == '.' || hostname && (!alnum(at(s-1)) || !alnum(at(s+1))) {
				return false
			}
			label = 1
			continue
		}
		if label > 63 || hostname && c != '-' && !alnum(c) {
			return false
		}
		label++
	}
	return true
}

func alnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// phpMAC: FILTER_VALIDATE_MAC, six groups of two hex digits joined by
// ":" or "-", or three groups of four joined by ".".
func phpMAC(s string) bool {
	var tokens, length int
	var sep byte
	switch {
	case len(s) == 14:
		tokens, length, sep = 3, 4, '.'
	case len(s) == 17 && (s[2] == '-' || s[2] == ':'):
		tokens, length, sep = 6, 2, s[2]
	default:
		return false
	}
	for i := 0; i < tokens; i++ {
		off := i * (length + 1)
		if i < tokens-1 && s[off+length] != sep {
			return false
		}
		for _, c := range []byte(s[off : off+length]) {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return false
			}
		}
	}
	return true
}

// urlChars: the characters FILTER_VALIDATE_URL keeps (FILTER_SANITIZE_URL)
const urlChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$-_.+!*'(),{}|\\^~[]`<>#%\";/?:@&="

var schemeRe = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9+.-]*):`)

// phpURL: FILTER_VALIDATE_URL: only URL characters; a scheme; a host
// unless the scheme is mailto, news or file; for http and https a host
// name or a bracketed IPv6 address; a port up to 65535.
func phpURL(s string) bool {
	for i := 0; i < len(s); i++ {
		if !strings.ContainsRune(urlChars, rune(s[i])) {
			return false
		}
	}
	m := schemeRe.FindStringSubmatch(s)
	if m == nil {
		return false
	}
	scheme, rest := m[1], s[len(m[0]):]
	host := ""
	if strings.HasPrefix(rest, "//") {
		auth := rest[2:]
		if i := strings.IndexAny(auth, "/?#"); i >= 0 {
			auth = auth[:i]
		}
		if i := strings.LastIndexByte(auth, '@'); i >= 0 {
			for _, u := range strings.SplitN(auth[:i], ":", 2) {
				if !userinfo(u) {
					return false
				}
			}
			auth = auth[i+1:]
		}
		host = auth
		if !strings.HasSuffix(auth, "]") {
			if i := strings.LastIndexByte(auth, ':'); i >= 0 {
				host = auth[:i]
				if p := auth[i+1:]; p != "" && (!ctypeDigit(p) || len(p) > 5 || mustAtoi(p) > 65535) {
					return false
				}
			}
		} else if i := strings.LastIndex(auth, "]:"); i >= 0 {
			host = auth[:i+1]
		}
	}
	if host == "" {
		return scheme == "mailto" || scheme == "news" || scheme == "file"
	}
	if strings.EqualFold(scheme, "http") || strings.EqualFold(scheme, "https") {
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			return phpIP(host[1:len(host)-1], false, true)
		}
		return phpDomain(host, true)
	}
	return true
}

func mustAtoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// userinfo: is_userinfo_valid of ext/filter.
func userinfo(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case alnum(c), strings.IndexByte("-._~!$&'()*+,;=:", c) >= 0:
		case c == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			i += 2
		default:
			return false
		}
	}
	return true
}

func isHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }
