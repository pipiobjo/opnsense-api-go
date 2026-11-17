// SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
// SPDX-License-Identifier: BSD-2-Clause

// Package opnsense is a client for the OPNsense API that adapts to the
// firewall it talks to: it detects the core version and the installed
// plugins, picks the matching capability data, and refuses to send
// resources, fields or values that version does not have (OPNsense would
// silently ignore them). After every write it reads the object back.
//
//	c, err := opnsense.New(ctx, opnsense.Config{URL: "https://fw.example", Key: k, Secret: s})
//	hosts, err := c.Entries("unbound/settings#hosts.host")
//	id, err := hosts.Add(ctx, opnsense.Values{"hostname": "nas", "domain": "example.com", "server": "192.0.2.10"})
//	err = hosts.Apply(ctx)
//
// A Client is safe for concurrent use.
package opnsense

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pipiobjo/opnsense-api-go/internal/transport"
	"github.com/pipiobjo/opnsense-api-go/opnsense/capability"
)

// Values maps field paths ("hostname", "general.enabled") to values: bool,
// int64 (or another integer type), string, or []string for list fields.
// Read values use exactly these types; bool and int fields that are empty
// on the firewall are nil.
type Values map[string]any

// Policy for combinations of core and plugin versions the capability data
// has not seen.
type Policy = capability.Policy

const (
	// AssumeNewestInSeries uses the nearest data of the same series and
	// reports a warning in Instance().Warnings. Read-back still catches
	// a field that does not behave as the data says.
	AssumeNewestInSeries = capability.AssumeNewestInSeries
	// Refuse fails New when any installed package is not an exact match.
	Refuse = capability.Refuse
)

// TLS settings: at most one of CAFile/CAPEM, PinSHA256 and
// InsecureSkipVerify. Without any of them the system roots are used. For a
// firewall with a self-signed certificate, prefer PinSHA256: it is as easy
// to set up as InsecureSkipVerify and keeps the API key safe.
type TLS struct {
	CAFile    string // PEM file with the CA that signed the firewall's certificate
	CAPEM     []byte // the same as bytes
	PinSHA256 string // SHA-256 of the firewall's certificate (hex, colons allowed)

	// InsecureSkipVerify turns certificate verification off. Anyone who can
	// intercept the connection can read the API key and secret and change
	// the firewall. Every client created with it carries InsecureWarning in
	// Instance().Warnings.
	InsecureSkipVerify bool
}

// InsecureWarning is the warning a client with InsecureSkipVerify carries.
const InsecureWarning = "TLS certificate verification is disabled (InsecureSkipVerify): the API key is exposed to anyone on the network path"

// Config of a client.
type Config struct {
	URL    string // https://host[:port]
	Key    string
	Secret string
	TLS    TLS

	// UnknownVersion decides what happens with versions the data has not
	// seen. Default: AssumeNewestInSeries.
	UnknownVersion Policy
	// Capabilities is the data to use. If nil, CapabilityDir is loaded.
	Capabilities *capability.Set
	// CapabilityDir is an unpacked "catalog" release: catalog.json and
	// capabilities/<package>.json.
	CapabilityDir string

	// AutoApply applies after every successful mutation.
	AutoApply bool

	// ReadOnly: the client reads but never changes the firewall. Every
	// changing method (Add, Set, Delete, Toggle, Settings.Set, Apply)
	// returns *ErrReadOnly before anything is sent, and the transport
	// refuses every POST except a search, independently of those checks.
	// Call is limited to GET on the get and search operations in the
	// capability data, plus the paths in ReadOnlyAllow. OPNsense cannot do
	// this itself: its privileges grant URL patterns, reading and writing
	// together.
	ReadOnly bool
	// ReadOnlyAllow names further paths Call may GET in read-only mode,
	// for endpoints that are not resource operations (logs, status). An
	// entry ending in "/*" allows everything below it. Only list endpoints
	// that change nothing: OPNsense does not mark them, and some change
	// state even on GET.
	ReadOnlyAllow []string

	Timeout      time.Duration // per request, default 60s
	ApplyTimeout time.Duration // apply endpoints, default 5m
	Logger       *slog.Logger  // debug log: method, path, status, duration; never bodies or credentials
	// HTTPClient replaces the built-in HTTP client, for example for a proxy
	// or tracing. Its transport then decides about TLS entirely, so it
	// cannot be combined with TLS settings (New refuses that).
	HTTPClient *http.Client
}

// Instance describes the detected firewall. The client returns a copy.
type Instance struct {
	Core     string            // core version as reported, e.g. 26.7.9_1
	Plugins  map[string]string // installed plugin -> version
	Resolved capability.Resolved
	// Notes: the data has another hotfix revision of this release, or this
	// plugin version from another core of the series, and that is used.
	// Usual after an update; nothing to do.
	Notes []string
	// ReadOnly: the client was created with Config.ReadOnly.
	ReadOnly bool
	// Warnings: a guess about a release or plugin version the data has
	// never seen, an incomplete detection, or disabled TLS verification.
	// Fields newer than the data are refused; read-back still checks every
	// write. Updating the capability data removes most of them.
	Warnings []string
}

// Client talks to one firewall.
type Client struct {
	cfg  Config
	t    *transport.Transport
	data *capability.Set
	inst Instance
	owns map[string][]string // resource -> packages that define it

	mu        sync.Mutex
	pending   map[string]uint64         // apply endpoint -> generation of the last mutation
	locks     map[string]*sync.Mutex    // per model class, and per apply endpoint ("apply:<path>")
	templates map[string]map[string]any // entry list -> its blank template (get without UUID)

	pluginsUnknown bool // the key may not read the plugin list
}

// New checks the data, connects, detects the firewall and resolves the
// capability data.
func New(ctx context.Context, cfg Config) (*Client, error) {
	data := cfg.Capabilities
	if data == nil {
		if cfg.CapabilityDir == "" {
			return nil, errors.New("opnsense: no capability data (Config.Capabilities or Config.CapabilityDir)")
		}
		// opened as a root: symbolic links cannot lead outside the directory
		root, err := os.OpenRoot(cfg.CapabilityDir)
		if err != nil {
			return nil, fmt.Errorf("opnsense: capability data: %w", err)
		}
		data, err = capability.Load(root.FS())
		root.Close()
		if err != nil {
			return nil, fmt.Errorf("opnsense: capability data: %w", err)
		}
	} else if err := data.Check(); err != nil {
		return nil, fmt.Errorf("opnsense: capability data: %w", err)
	}
	if cfg.ReadOnly && cfg.AutoApply {
		return nil, errors.New("opnsense: Config.ReadOnly and Config.AutoApply contradict each other")
	}
	for _, p := range cfg.ReadOnlyAllow {
		if err := transport.CheckPath(strings.TrimSuffix(p, "/*")); err != nil {
			return nil, fmt.Errorf("opnsense: Config.ReadOnlyAllow: %w", err)
		}
	}
	if cfg.HTTPClient != nil && (cfg.TLS.PinSHA256 != "" || cfg.TLS.CAFile != "" || len(cfg.TLS.CAPEM) > 0 || cfg.TLS.InsecureSkipVerify) {
		return nil, errors.New("opnsense: Config.HTTPClient replaces the built-in transport and its TLS settings; set either HTTPClient or TLS, not both")
	}
	tc := transport.Config{URL: cfg.URL, Key: cfg.Key, Secret: cfg.Secret, Pin: cfg.TLS.PinSHA256,
		CAPEM: cfg.TLS.CAPEM, Insecure: cfg.TLS.InsecureSkipVerify, Timeout: cfg.Timeout, Logger: cfg.Logger, HTTP: cfg.HTTPClient,
		ReadOnly: cfg.ReadOnly}
	if cfg.TLS.CAFile != "" {
		pem, err := os.ReadFile(cfg.TLS.CAFile)
		if err != nil {
			return nil, fmt.Errorf("opnsense: CA file: %w", err)
		}
		tc.CAPEM = append(append([]byte{}, tc.CAPEM...), pem...)
	}
	t, err := transport.New(tc)
	if err != nil {
		return nil, err
	}
	if cfg.ApplyTimeout == 0 {
		cfg.ApplyTimeout = 5 * time.Minute
	}
	c := &Client{cfg: cfg, t: t, data: data, owns: map[string][]string{},
		pending: map[string]uint64{}, locks: map[string]*sync.Mutex{}, templates: map[string]map[string]any{}}
	for pkg, d := range data.Docs {
		for id := range d.Resources {
			c.owns[id] = append(c.owns[id], pkg)
		}
	}
	for id := range c.owns {
		sort.Strings(c.owns[id])
	}
	if err := c.detect(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// Instance returns a copy of what was detected, with notes and warnings.
func (c *Client) Instance() Instance {
	in := c.inst
	in.Plugins = copyMap(c.inst.Plugins)
	in.Warnings = append([]string(nil), c.inst.Warnings...)
	in.Notes = append([]string(nil), c.inst.Notes...)
	in.Resolved.Notes = append([]string(nil), c.inst.Resolved.Notes...)
	in.Resolved.Warnings = append([]string(nil), c.inst.Resolved.Warnings...)
	in.Resolved.Packages = make(map[string]*capability.Resolution, len(c.inst.Resolved.Packages))
	for k, v := range c.inst.Resolved.Packages {
		r := *v
		in.Resolved.Packages[k] = &r
	}
	return in
}

// Data returns the capability data in use. It is shared: do not modify it.
func (c *Client) Data() *capability.Set { return c.data }

func copyMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

type pkgInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Installed string `json:"installed"`
}

func (c *Client) detect(ctx context.Context) error {
	var info struct {
		ProductVersion string    `json:"product_version"`
		ProductID      string    `json:"product_id"`
		Package        []pkgInfo `json:"package"`
		Plugin         []pkgInfo `json:"plugin"`
	}
	inst := Instance{Plugins: map[string]string{}}
	err := c.t.Get(ctx, "/api/core/firmware/info", nil, &info)
	if err != nil && !errors.Is(err, ErrForbidden) {
		// only a missing privilege has a fallback; anything else (wrong key,
		// HTTP 500, a timeout) would leave a client that believes no plugin
		// is installed
		return fmt.Errorf("opnsense: detecting the firmware (GET /api/core/firmware/info): %w", err)
	}
	if err == nil {
		inst.Core = info.ProductVersion
		for _, p := range info.Package {
			if p.Name == info.ProductID && p.Installed == "1" && p.Version != "" {
				inst.Core = p.Version
			}
			if strings.HasPrefix(p.Name, "os-") && p.Installed == "1" {
				inst.Plugins[p.Name] = p.Version
			}
		}
		for _, p := range info.Plugin {
			if p.Installed == "1" {
				inst.Plugins[p.Name] = p.Version
			}
		}
	} else {
		// a key without the firmware privilege (403): the core version alone,
		// plugins unknown
		var st struct {
			ProductVersion string `json:"product_version"`
			Product        struct {
				ProductVersion string `json:"product_version"`
			} `json:"product"`
		}
		if err2 := c.t.Get(ctx, "/api/core/firmware/status", nil, &st); err2 != nil {
			return fmt.Errorf("opnsense: detecting the firmware: %w", errors.Join(err, err2))
		}
		inst.Core = st.ProductVersion
		if inst.Core == "" {
			inst.Core = st.Product.ProductVersion
		}
		inst.Warnings = append(inst.Warnings, "plugin list not available ("+err.Error()+"); only the core is used")
		c.pluginsUnknown = true
	}
	if inst.Core == "" {
		return errors.New("opnsense: the firewall did not report its version")
	}
	res, err := c.data.Resolve(inst.Core, inst.Plugins, c.cfg.UnknownVersion)
	if err != nil {
		return fmt.Errorf("opnsense: %w", err)
	}
	inst.Resolved = *res
	if c.cfg.TLS.InsecureSkipVerify {
		inst.Warnings = append([]string{InsecureWarning}, inst.Warnings...)
		if c.cfg.Logger != nil {
			c.cfg.Logger.Warn(InsecureWarning)
		}
	}
	inst.Warnings = append(inst.Warnings, res.Warnings...)
	inst.Notes = append(inst.Notes, res.Notes...)
	inst.ReadOnly = c.cfg.ReadOnly
	c.inst = inst
	return nil
}

// bound is a resource resolved for this firewall.
type bound struct {
	c        *Client
	id       string
	pkg      string
	version  string
	frag     string
	res      *capability.Resource
	api      *capability.API
	verified *capability.ResVerify
	readOnly string // why writes are refused, "" if they are allowed
}

// writable refuses writes in read-only mode and to a package older than
// its data (ErrReadOnly).
func (b *bound) writable() error {
	if b.c.cfg.ReadOnly {
		return &ErrReadOnly{Resource: b.id, Package: b.pkg, Have: b.version, Reason: readOnlyModeReason, Mode: true}
	}
	if b.readOnly == "" {
		return nil
	}
	return &ErrReadOnly{Resource: b.id, Package: b.pkg, Have: b.version, Reason: b.readOnly}
}

func (c *Client) bind(id, kind string) (*bound, error) {
	pkgs := c.owns[id]
	if len(pkgs) == 0 {
		return nil, &ErrNotAvailable{Resource: id}
	}
	var first *ErrNotAvailable
	for _, pkg := range pkgs {
		r := c.data.Docs[pkg].Resources[id]
		res := c.inst.Resolved.Packages[pkg]
		if res != nil && res.Fragment != "" && r.Available(res.Fragment) {
			if r.Kind != kind {
				return nil, &ErrWrongKind{Resource: id, Kind: r.Kind, Want: kind}
			}
			api := r.APIFor(res.Fragment)
			if api == nil {
				return nil, fmt.Errorf("opnsense: %s: no API variant for fragment %s", id, res.Fragment)
			}
			b := &bound{c: c, id: id, pkg: pkg, version: res.Version, frag: res.Fragment, res: r,
				api: api, verified: r.Verified[res.Fragment]}
			if res.ReadOnly {
				b.readOnly = res.Warning
			}
			// a resource of the core needs the core to be writable as well
			if core := c.inst.Resolved.Packages[capability.CorePackage]; pkg != capability.CorePackage && core != nil && core.ReadOnly && b.readOnly == "" {
				b.readOnly = core.Warning
			}
			return b, nil
		}
		if first == nil {
			e := &ErrNotAvailable{Resource: id, Package: pkg, AvailableIn: c.versions(pkg, r.In)}
			if res != nil {
				e.Have = res.Version
			} else if pkg != capability.CorePackage {
				e.PluginsUnknown = c.pluginsUnknown
			}
			first = e
		}
	}
	return nil, first
}

// versions lists the package versions of the given fragments.
func (c *Client) versions(pkg string, frags []string) []string {
	d := c.data.Docs[pkg]
	seen := map[string]bool{}
	var out []string
	for _, h := range frags {
		for _, v := range d.Fragments[h].Versions {
			if !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return capability.CompareVersions(out[i], out[j]) < 0 })
	return out
}

func (c *Client) lock(key string) func() {
	c.mu.Lock()
	m := c.locks[key]
	if m == nil {
		m = &sync.Mutex{}
		c.locks[key] = m
	}
	c.mu.Unlock()
	m.Lock()
	return m.Unlock
}

func (c *Client) markPending(apply string) {
	if apply == "" {
		return
	}
	c.mu.Lock()
	c.pending[apply]++
	c.mu.Unlock()
}

// post sends a change. If it reached the firewall but the outcome is
// unknown, the apply endpoint is marked pending: the change may be saved.
func (c *Client) post(ctx context.Context, path string, body, out any, apply string) error {
	err := c.t.Post(ctx, path, body, out, 0)
	if errors.Is(err, ErrOutcomeUnknown) {
		c.markPending(apply)
	}
	return err
}

// Pending lists the apply endpoints that Apply would call.
func (c *Client) Pending() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.pending))
	for p := range c.pending {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Apply activates saved changes: every pending apply endpoint is called
// once. Writes alone change only the stored configuration.
//
// The pending list lives only in this Client: a new process (the next
// provider run after a failed apply) starts with none. Entries.Apply and
// Settings.Apply call their endpoint unconditionally for that reason.
func (c *Client) Apply(ctx context.Context) error {
	if c.cfg.ReadOnly {
		return &ErrReadOnly{Resource: "apply", Reason: readOnlyModeReason, Mode: true}
	}
	var errs []error
	for _, p := range c.Pending() {
		if err := c.applyEndpoint(ctx, p, false); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// applyEndpoint calls one apply endpoint: if it is pending, or always with
// force. A mutation that is saved while the call runs keeps the endpoint
// pending: the generation is compared, not just cleared.
func (c *Client) applyEndpoint(ctx context.Context, p string, force bool) error {
	if c.cfg.ReadOnly {
		return &ErrReadOnly{Resource: p, Reason: readOnlyModeReason, Mode: true}
	}
	if p == "" {
		return nil // the resource has no apply endpoint: saved is active
	}
	defer c.lock("apply:" + p)()
	c.mu.Lock()
	gen, ok := c.pending[p]
	c.mu.Unlock()
	if !ok && !force {
		return nil
	}
	var resp map[string]any
	if err := c.t.Post(ctx, p, nil, &resp, c.cfg.ApplyTimeout); err != nil {
		return err
	}
	if !applyOK(resp) {
		return &ErrApply{Endpoint: p, Answer: transport.Trunc([]byte(fmt.Sprint(resp)))}
	}
	c.mu.Lock()
	if cur, ok := c.pending[p]; ok && cur == gen {
		delete(c.pending, p)
	}
	c.mu.Unlock()
	return nil
}

// applyOK: {"status": "ok"} from most service controllers, {"result":
// "ok"} from some (openvpn on 26.7.9). Anything else is not success.
func applyOK(resp map[string]any) bool {
	for _, k := range []string{"status", "result"} {
		if v, _ := resp[k].(string); strings.EqualFold(strings.TrimSpace(v), "ok") {
			return true
		}
	}
	return false
}

// finish completes a mutation that reached the firewall: the apply
// endpoint is already pending (markPending right after the request); the
// read-back result comes first, then AutoApply. Both errors are returned,
// so a failing apply cannot hide a value the firewall did not keep.
func (c *Client) finish(ctx context.Context, apply string, readBack error) error {
	var applyErr error
	if c.cfg.AutoApply && apply != "" {
		applyErr = c.applyEndpoint(ctx, apply, false)
	}
	return errors.Join(readBack, applyErr)
}

// Call sends a request to any API path of this firewall and decodes the
// JSON answer into out: the escape hatch for endpoints that are not
// resource operations (service actions, diagnostics). Nothing is checked
// against the capability data, and nothing is read back. method is GET or
// POST; body is sent as JSON with POST.
func (c *Client) Call(ctx context.Context, method, path string, body, out any) error {
	if c.cfg.ReadOnly {
		if method != http.MethodGet {
			return &ErrReadOnly{Resource: method + " " + path, Reason: readOnlyModeReason + "; Call sends only GET (use Entries.List for a search)", Mode: true}
		}
		if !c.readAllowed(path) {
			return &ErrReadOnly{Resource: "GET " + path, Reason: readOnlyModeReason + "; not a get or search operation in the capability data (add it to Config.ReadOnlyAllow if it changes nothing)", Mode: true}
		}
	}
	switch method {
	case http.MethodGet:
		if body != nil {
			return errors.New("opnsense: GET takes no body")
		}
		return c.t.Get(ctx, path, nil, out)
	case http.MethodPost:
		return c.t.Post(ctx, path, body, out, 0)
	}
	return fmt.Errorf("opnsense: method %q not supported", method)
}

const readOnlyModeReason = "the client is in read-only mode (Config.ReadOnly)"

// readAllowed: in read-only mode, Call may GET the get and search
// operations of the resources this firewall has (with arguments below
// them, such as an entry ID), and the paths in Config.ReadOnlyAllow.
func (c *Client) readAllowed(path string) bool {
	under := func(p, base string) bool { return p == base || strings.HasPrefix(p, base+"/") }
	for _, a := range c.cfg.ReadOnlyAllow {
		if base, ok := strings.CutSuffix(a, "/*"); ok {
			if under(path, base) {
				return true
			}
		} else if path == a {
			return true
		}
	}
	for pkg, d := range c.data.Docs {
		res := c.inst.Resolved.Packages[pkg]
		if res == nil || res.Fragment == "" {
			continue
		}
		for _, r := range d.Resources {
			api := r.APIFor(res.Fragment)
			if api == nil {
				continue
			}
			for _, name := range []string{"get", "search"} {
				if op := api.Operations[name]; op != nil && under(path, op.Path) {
					return true
				}
			}
		}
	}
	return false
}
