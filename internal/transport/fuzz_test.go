// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

package transport

import (
	"net/url"
	"path"
	"strings"
	"testing"
)

// FuzzCheckPath: every path CheckPath accepts stays below /api/, has no
// "." or ".." segment, and reaches the server unchanged (nothing to
// escape, nothing a URL parser would reinterpret).
func FuzzCheckPath(f *testing.F) {
	for _, s := range []string{
		"/api/core/firmware/status", "/api/unbound/settings/getHostOverride/00000000-0000-4000-8000-000000000001",
		"/api/interfaces/assignment/getItem/wan", "/api/x/y/../../z", "/api/x/%2e%2e/y", "/api/x//y",
		"/api/x/y?z=1", "/api/x/y#f", "/api/x/y?", "/api/x/y#", "/api/x/y%", "/api/x/y;a", "/api/x/y\\z", "/api/x/y\x00", "/api/аpi/y", "/api/./x", "//api/x", "/api/x/y/",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		if CheckPath(p) != nil {
			return
		}
		if !strings.HasPrefix(p, "/api/") {
			t.Fatalf("accepted outside /api/: %q", p)
		}
		if path.Clean(p) != p {
			t.Fatalf("accepted a path that cleans to something else: %q -> %q", p, path.Clean(p))
		}
		u, err := url.Parse("https://192.0.2.1" + p)
		if err != nil || u.Path != p || u.RawQuery != "" || u.Fragment != "" || u.EscapedPath() != p {
			t.Fatalf("accepted %q, but the URL reads it as path %q query %q fragment %q (%v)", p, u.Path, u.RawQuery, u.Fragment, err)
		}
	})
}
