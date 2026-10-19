package netguard

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// AllowPrivateFromEnv reads AGENT_VAULT_ALLOW_PRIVATE_RANGES and returns whether
// the proxy should allow connections to private/reserved IP ranges (RFC-1918,
// loopback, link-local, IPv6 ULA, CGN). Defaults to false (block) when unset
// or unparseable — the safe default for network-exposed deployments. Cloud
// metadata endpoints are blocked regardless of this setting.
func AllowPrivateFromEnv() bool {
	v := os.Getenv("AGENT_VAULT_ALLOW_PRIVATE_RANGES")
	if v == "" {
		return false
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false
	}
	return b
}

// AllowlistFromEnv reads AGENT_VAULT_NETWORK_ALLOWLIST and returns a list of
// IP networks to allow when private-range blocking is on.
func AllowlistFromEnv() []net.IPNet {
	return ParseCIDRList(os.Getenv("AGENT_VAULT_NETWORK_ALLOWLIST"), "AGENT_VAULT_NETWORK_ALLOWLIST")
}

// ParseCIDRList parses a comma-separated list of CIDRs or bare IPs. Bare IPv4
// addresses are expanded to /32, bare IPv6 to /128. Invalid entries are logged
// via slog.Warn and skipped. Entries that cover an entire address family
// (mask 0, i.e. 0.0.0.0/0 or ::/0) are accepted but logged as warnings —
// they're rarely intended and effectively disable any per-range policy.
// envName labels the source in log messages.
func ParseCIDRList(raw, envName string) []net.IPNet {
	if raw == "" {
		return nil
	}

	var out []net.IPNet
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		cidr := p
		if !strings.Contains(p, "/") {
			ip := net.ParseIP(p)
			if ip == nil {
				slog.Warn("netguard: invalid IP, skipping", //nolint:gosec // G706: structured slog attrs, handlers quote control chars
					slog.String("env", envName), slog.String("value", p))
				continue
			}
			if ip.To4() != nil {
				cidr = p + "/32"
			} else {
				cidr = p + "/128"
			}
		}

		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			slog.Warn("netguard: invalid CIDR, skipping", //nolint:gosec // G706: structured slog attrs, handlers quote control chars
				slog.String("env", envName), slog.String("value", p), slog.String("error", err.Error()))
			continue
		}

		if mask, _ := ipNet.Mask.Size(); mask == 0 {
			slog.Warn("netguard: CIDR list entry covers an entire address family", //nolint:gosec // G706: structured slog attrs, handlers quote control chars
				slog.String("env", envName), slog.String("value", p))
		}

		out = append(out, *ipNet)
	}

	if len(out) > 0 {
		slog.Debug("netguard: loaded CIDR list", //nolint:gosec // G706: structured slog attrs, handlers quote control chars
			slog.String("env", envName), slog.Int("count", len(out)))
	}

	return out
}

// alwaysBlocked contains IP ranges that are blocked regardless of policy.
// These are metadata service endpoints and other dangerous destinations.
var alwaysBlocked = []net.IPNet{
	// AWS/GCP/Azure IMDS
	parseCIDR("169.254.169.254/32"),
	// AWS IMDSv2 IPv6
	parseCIDR("fd00:ec2::254/128"),
}

// privateRanges contains RFC-1918 and other private/reserved ranges.
// Blocked unless AGENT_VAULT_ALLOW_PRIVATE_RANGES=true or the IP is in the
// AGENT_VAULT_NETWORK_ALLOWLIST.
var privateRanges = []net.IPNet{
	// IPv4 private
	parseCIDR("10.0.0.0/8"),
	parseCIDR("172.16.0.0/12"),
	parseCIDR("192.168.0.0/16"),
	// IPv4 loopback
	parseCIDR("127.0.0.0/8"),
	// IPv4 link-local
	parseCIDR("169.254.0.0/16"),
	// IPv4 shared address space (CGN)
	parseCIDR("100.64.0.0/10"),
	// IPv6 loopback
	parseCIDR("::1/128"),
	// IPv6 link-local
	parseCIDR("fe80::/10"),
	// IPv6 unique local
	parseCIDR("fc00::/7"),
	// 0.0.0.0 and :: (unspecified; connecting to them reaches localhost)
	parseCIDR("0.0.0.0/32"),
	parseCIDR("::/128"),
}

func parseCIDR(s string) net.IPNet {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		panic("netguard: bad CIDR: " + s)
	}
	return *ipNet
}

// isBlockedIP checks if an IP is blocked. When allowPrivate is false,
// private/reserved ranges are blocked unless the IP is in the allowlist.
// IMDS endpoints are always blocked, even when allowlisted.
func isBlockedIP(ip net.IP, allowPrivate bool, allowed []net.IPNet) bool {
	for _, n := range alwaysBlocked {
		if n.Contains(ip) {
			return true
		}
	}

	if allowPrivate {
		return false
	}

	for _, n := range allowed {
		if n.Contains(ip) {
			return false
		}
	}

	for _, n := range privateRanges {
		if n.Contains(ip) {
			return true
		}
	}

	return false
}

// SafeDialContext returns a DialContext function that blocks connections to
// forbidden IP ranges. When allowPrivate is true, only IMDS endpoints are
// blocked. When false, private/reserved ranges are also blocked unless
// allowlisted via AGENT_VAULT_NETWORK_ALLOWLIST, or the dial names a host
// listed in AGENT_VAULT_PRIVATE_HOSTS (see PrivateHosts).
//
// Resolution and address selection are left to net.Dialer, which tries every
// resolved address and races IPv6 against IPv4 (RFC 6555 Fast Fallback), so
// one broken address family does not fail or stall the dial. The policy check
// runs in the dialer's ControlContext hook on each address right before
// connect, so blocked addresses are skipped and DNS rebinding cannot swap in
// an unchecked IP between validation and connection.
func SafeDialContext(allowPrivate bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	var allowed []net.IPNet
	if !allowPrivate {
		allowed = AllowlistFromEnv()
	}
	setting, file := os.Getenv("AGENT_VAULT_EGRESS_RANGES"), os.Getenv("AGENT_VAULT_EGRESS_RANGES_FILE")
	public := withEgressRanges(newSafeDialer(allowPrivate, allowed), setting, file)
	if allowPrivate {
		return public.DialContext
	}
	internal := withEgressRanges(newSafeDialer(true, nil), setting, file)
	return withPrivateHosts(public, internal, PrivateHostsFromEnv())
}

// PrivateHosts names the internal hosts whose private addresses the broker
// may dial, so an internal target (Vault, a database, an internal API) is
// named in configuration by host name and its addresses are looked up at
// run time, never written down. Each entry is a host name matched exactly,
// or "*." and a suffix of at least two labels, matching every name under
// that suffix (not the suffix itself). Matching ignores case and a trailing
// dot.
//
// A dial whose target is a listed name may reach the private addresses DNS
// returns for it. Everything else keeps the private-range block: an IP
// literal, and any other name, even one that resolves to the same private
// address, so a vendor's name rebound to an internal address is still
// refused. Metadata endpoints stay blocked for every name, and the egress
// ranges (AGENT_VAULT_EGRESS_RANGES and its file) still confine a listed
// name's dials when they are set.
type PrivateHosts struct {
	exact    map[string]bool
	suffixes []string // each with its leading dot
}

// PrivateHostsFromEnv reads AGENT_VAULT_PRIVATE_HOSTS.
func PrivateHostsFromEnv() PrivateHosts {
	return ParsePrivateHosts(os.Getenv("AGENT_VAULT_PRIVATE_HOSTS"), "AGENT_VAULT_PRIVATE_HOSTS")
}

// ParsePrivateHosts parses a comma-separated host list. Entries that are not
// host names (an address, a range, a URL, a wildcard anywhere but the whole
// leftmost label, or one over a suffix shorter than two labels) are logged
// and skipped, so a bad entry never widens what is allowed. envName labels
// the source in log messages.
func ParsePrivateHosts(raw, envName string) PrivateHosts {
	h := PrivateHosts{exact: map[string]bool{}}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(entry), "."))
		if entry == "" {
			continue
		}
		suffix, wildcard := strings.CutPrefix(entry, "*.")
		if !hostName(suffix) || (wildcard && strings.Count(suffix, ".") < 1) {
			slog.Warn("netguard: private hosts entry is not a host name or an allowed wildcard, skipping", //nolint:gosec // G706: structured slog attrs, handlers quote control chars
				slog.String("env", envName), slog.String("value", entry))
			continue
		}
		if wildcard {
			h.suffixes = append(h.suffixes, "."+suffix)
		} else {
			h.exact[suffix] = true
		}
	}
	return h
}

// Match reports whether host, a dial target's host part, is a listed name.
// An address never matches.
func (h PrivateHosts) Match(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if _, err := netip.ParseAddr(host); err == nil || !hostName(host) {
		return false
	}
	if h.exact[host] {
		return true
	}
	for _, suffix := range h.suffixes {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

func (h PrivateHosts) empty() bool { return len(h.exact) == 0 && len(h.suffixes) == 0 }

// hostName reports whether s is a DNS host name: dot-separated labels of
// letters, digits and inner hyphens, each 1 to 63 bytes, 253 bytes in all,
// the last starting with a letter as every top-level domain does. That last
// rule keeps out every form a C resolver reads as an IPv4 address
// ("127.1", "0x7f.1", "1.0x7f").
func hostName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	if last := labels[len(labels)-1]; last == "" || !asciiLetter(last[0]) {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			if c := label[i]; !asciiLetter(c) && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

func asciiLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// withPrivateHosts sends a dial whose target is a listed private host
// through internal, which allows private ranges, and every other dial through
// public. With no host listed it is public alone.
func withPrivateHosts(public, internal *net.Dialer, hosts PrivateHosts) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if hosts.empty() {
		return public.DialContext
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if host, _, err := net.SplitHostPort(addr); err == nil && hosts.Match(host) {
			return internal.DialContext(ctx, network, addr)
		}
		return public.DialContext(ctx, network, addr)
	}
}

func newSafeDialer(allowPrivate bool, allowed []net.IPNet) *net.Dialer {
	return &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		ControlContext: func(_ context.Context, _, address string, _ syscall.RawConn) error {
			err := checkDialAddress(address, allowPrivate, allowed)
			if err != nil {
				// A refused address may be skipped in favor of another one, in
				// which case the request succeeds and this is the only trace.
				slog.Warn("netguard: dial attempt refused", //nolint:gosec // G706: structured slog attrs, handlers quote control chars
					slog.String("address", address), slog.String("error", err.Error()))
			}
			return err
		},
	}
}

// checkDialAddress applies the network policy to the ip:port net.Dialer is
// about to connect to. Anything that does not parse as an IP address is
// rejected, so an unexpected address form cannot slip past the policy.
func checkDialAddress(address string, allowPrivate bool, allowed []net.IPNet) error {
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("netguard: cannot validate dial address %q: %w", address, err)
	}
	ip := addrPort.Addr().Unmap()
	if isBlockedIP(ip.AsSlice(), allowPrivate, allowed) {
		return fmt.Errorf("netguard: connection to %s blocked by network policy", ip)
	}
	return nil
}

// withEgressRanges confines d to the AGENT_VAULT_EGRESS_RANGES data-plane
// ranges, every destination public or private: the broker's own
// least-privilege layer beneath the catalog's host allowlist. The ranges are
// checked in the same ControlContext hook as the network policy, on each
// address right before connect. With neither setting nor file set, d is
// unchanged; a set but unparseable setting allows nothing beyond the file's
// addresses, rather than everything.
//
// file, when set (AGENT_VAULT_EGRESS_RANGES_FILE), names a file of single
// addresses that also count as egress ranges, re-read while the process runs:
// a job resolves the catalog's host names and writes it, so a host's addresses
// live outside the deployment's configuration and can change without a
// restart. Setting it confines d even when setting is empty. See fileRanges.
func withEgressRanges(d *net.Dialer, setting, file string) *net.Dialer {
	if strings.TrimSpace(setting) == "" && strings.TrimSpace(file) == "" {
		return d
	}
	egress := ParseCIDRList(setting, "AGENT_VAULT_EGRESS_RANGES")
	var extra *fileRanges
	if strings.TrimSpace(file) != "" {
		extra = sharedFileRanges(strings.TrimSpace(file))
	}
	policy := d.ControlContext
	d.ControlContext = func(ctx context.Context, network, address string, c syscall.RawConn) error {
		if err := policy(ctx, network, address, c); err != nil {
			return err
		}
		err := checkEgressAddress(address, egress)
		if err != nil && extra != nil && checkEgressAddress(address, extra.current()) == nil {
			err = nil
		}
		if err != nil {
			attrs := []any{slog.String("address", address), slog.String("error", err.Error())}
			if extra != nil {
				attrs = append(attrs, slog.String("egress_file", extra.path))
			}
			slog.Warn("netguard: dial attempt outside egress ranges refused", attrs...) //nolint:gosec // G706: structured slog attrs, handlers quote control chars
		}
		return err
	}
	return d
}

// fileRangesInterval is how long a read of the egress ranges file is reused.
const fileRangesInterval = 5 * time.Second

// fileRanges holds the addresses read from an egress ranges file. The file
// lists single addresses (an IPv4 or IPv6 address, or one with /32 or /128),
// separated by commas, spaces or new lines, with # comments. A missing file
// adds nothing until a good read, since the job that writes it may not have
// run yet. A file with no address, or with any other entry (a wider range, a
// name, garbage), is refused whole and the last good set stays, so a failed
// or bad write never widens egress and never cuts working connections. After a
// good read, a missing, unreadable or empty file keeps that set: removing
// the file revokes nothing, so revoke by writing a shorter list. The broker
// cannot tell a file cut off mid-write from a whole one, so the writer must
// replace it atomically (write a temporary file and rename it; a Kubernetes
// ConfigMap mounted as a directory does, but a subPath mount never updates).
// The private and metadata blocks apply to these addresses as to every other:
// a private address in the file serves only a dial to a listed private host
// (PrivateHosts), so a bad write cannot open an internal address to any other
// name.
type fileRanges struct {
	path    string
	mu      sync.Mutex
	read    time.Time
	content string
	nets    []net.IPNet
	now     func() time.Time
	absent  bool // logged that the file is not there before its first good read
}

var fileRangesByPath sync.Map // path -> *fileRanges

func sharedFileRanges(path string) *fileRanges {
	f, _ := fileRangesByPath.LoadOrStore(path, &fileRanges{path: path, now: time.Now})
	return f.(*fileRanges)
}

func (f *fileRanges) current() []net.IPNet {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.read.IsZero() && f.now().Sub(f.read) < fileRangesInterval {
		return f.nets
	}
	f.read = f.now()
	data, err := os.ReadFile(f.path) //nolint:gosec // G703: the path is the operator's AGENT_VAULT_EGRESS_RANGES_FILE setting, not request input
	switch {
	case errors.Is(err, fs.ErrNotExist):
		switch {
		case f.content != "":
			slog.Warn("netguard: egress ranges file is gone; keeping the last addresses read", slog.String("path", f.path)) //nolint:gosec // G706: structured slog attrs
		case !f.absent:
			// Once, so a mistyped path or a mount that never arrives is told
			// apart from a writer that has not run yet.
			f.absent = true
			slog.Warn("netguard: egress ranges file not there yet; adding no addresses until it is written", slog.String("path", f.path)) //nolint:gosec // G706: structured slog attrs
		}
		return f.nets
	case err != nil:
		slog.Warn("netguard: egress ranges file unreadable; keeping the last addresses read", //nolint:gosec // G706: structured slog attrs
			slog.String("path", f.path), slog.String("error", err.Error()))
		return f.nets
	case string(data) == f.content:
		return f.nets
	}
	nets, err := parseHostAddresses(string(data))
	if err != nil {
		slog.Warn("netguard: egress ranges file refused; keeping the last addresses read", //nolint:gosec // G706: structured slog attrs
			slog.String("path", f.path), slog.String("error", err.Error()))
		return f.nets
	}
	f.content, f.nets = string(data), nets
	slog.Info("netguard: egress ranges file read", slog.String("path", f.path), slog.Int("addresses", len(nets))) //nolint:gosec // G706: structured slog attrs
	return f.nets
}

// parseHostAddresses parses an egress ranges file: single addresses only.
func parseHostAddresses(raw string) ([]net.IPNet, error) {
	var out []net.IPNet
	for n, line := range strings.Split(raw, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		for _, field := range strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\r' }) {
			// Errors name the line, never the entry: a path set to the wrong
			// file must not copy that file's contents into the log.
			prefix, err := netip.ParsePrefix(field)
			if err != nil {
				addr, aerr := netip.ParseAddr(field)
				if aerr != nil || addr.Zone() != "" {
					return nil, fmt.Errorf("line %d: an entry is not an address", n+1)
				}
				prefix = netip.PrefixFrom(addr, addr.BitLen())
			}
			if prefix.Bits() != prefix.Addr().BitLen() {
				return nil, fmt.Errorf("line %d: an entry is a range; only single addresses are allowed", n+1)
			}
			addr := prefix.Addr().Unmap()
			out = append(out, net.IPNet{IP: addr.AsSlice(), Mask: net.CIDRMask(addr.BitLen(), addr.BitLen())})
		}
	}
	if len(out) == 0 {
		// A writer that resolved nothing must not cut every address it gave before.
		return nil, errors.New("no address listed")
	}
	return out, nil
}

// checkEgressAddress reports an error unless the ip:port the dialer is about
// to connect to lies inside one of the egress ranges.
func checkEgressAddress(address string, egress []net.IPNet) error {
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("netguard: cannot validate dial address %q: %w", address, err)
	}
	ip := addrPort.Addr().Unmap()
	for _, n := range egress {
		if n.Contains(ip.AsSlice()) {
			return nil
		}
	}
	return fmt.Errorf("netguard: connection to %s blocked by network policy", ip)
}
