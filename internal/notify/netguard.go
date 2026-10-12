package notify

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"

	"github.com/rs/zerolog/log"
)

// lookupIPAddrFunc resolves a host name. Tests inject one to simulate DNS
// rebinding (a resolver returning different answers per call).
type lookupIPAddrFunc func(ctx context.Context, host string) ([]net.IPAddr, error)

// dialFunc dials an already-vetted "ip:port" address.
type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// blockedNotificationPrefixes lists every range a notification destination
// must never reach: anything that is not globally routable unicast.
var blockedNotificationPrefixes = mustPrefixes(
	// IPv4
	"0.0.0.0/8",       // "this network", includes 0.0.0.0
	"10.0.0.0/8",      // private
	"100.64.0.0/10",   // CGNAT shared address space
	"127.0.0.0/8",     // loopback
	"169.254.0.0/16",  // link-local, cloud metadata
	"172.16.0.0/12",   // private
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // TEST-NET-1
	"192.88.99.0/24",  // deprecated 6to4 relay anycast
	"192.168.0.0/16",  // private
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24",  // TEST-NET-3
	"224.0.0.0/4",     // multicast
	"240.0.0.0/4",     // reserved, includes 255.255.255.255 broadcast
	// IPv6
	"::/96",          // unspecified, loopback, IPv4-compatible
	"::ffff:0:0/96",  // IPv4-mapped (also unmapped and rechecked as IPv4)
	"64:ff9b::/96",   // NAT64 well-known prefix
	"64:ff9b:1::/48", // local-use NAT64
	"100::/64",       // discard-only
	"2001::/23",      // IETF protocol assignments, includes Teredo
	"2001:db8::/32",  // documentation
	"2002::/16",      // 6to4 (embeds an IPv4 address)
	"3fff::/20",      // documentation
	"fc00::/7",       // unique local
	"fe80::/10",      // link-local
	"fec0::/10",      // deprecated site-local
	"ff00::/8",       // multicast
)

func mustPrefixes(values ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		out = append(out, netip.MustParsePrefix(value))
	}
	return out
}

// isBlockedNotificationAddr reports whether addr is anything other than a
// globally routable unicast address.
func isBlockedNotificationAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	addr = addr.WithZone("")
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return true
	}
	for _, prefix := range blockedNotificationPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func allowPrivateNotificationURLs() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("HIBOU_ALLOW_PRIVATE_NOTIFICATION_URLS")), "true")
}

// guardedNotificationDialContext returns a DialContext that resolves the
// destination once, rejects it if any resolved address is not globally
// routable, and dials the vetted IP directly so a second DNS answer
// (rebinding) is never used. The dialer's Control hook re-checks the socket's
// actual peer address as a backstop.
func guardedNotificationDialContext(dialer *net.Dialer) dialFunc {
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	guarded := *dialer
	guarded.Control = notificationDialControl
	return newGuardedDial(net.DefaultResolver.LookupIPAddr, guarded.DialContext)
}

func newGuardedDial(lookup lookupIPAddrFunc, dial dialFunc) dialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if allowPrivateNotificationURLs() {
			return dial(ctx, network, address)
		}
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("notification destination %q: %w", address, err)
		}
		ips, err := resolveNotificationAddrs(ctx, lookup, host)
		if err != nil {
			return nil, err
		}
		blocked := make([]string, 0, len(ips))
		for _, ip := range ips {
			if isBlockedNotificationAddr(ip) {
				blocked = append(blocked, ip.String())
			}
		}
		if len(blocked) > 0 {
			log.Warn().Str("address", address).Strs("blocked_ips", blocked).Msg("blocked private notification destination")
			return nil, fmt.Errorf("notification destination %q resolves to a blocked address", address)
		}
		var lastErr error
		for _, ip := range ips {
			conn, dialErr := dial(ctx, network, net.JoinHostPort(ip.String(), port))
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
			if ctx.Err() != nil {
				break
			}
		}
		return nil, lastErr
	}
}

func resolveNotificationAddrs(ctx context.Context, lookup lookupIPAddrFunc, host string) ([]netip.Addr, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, errors.New("notification destination host is empty")
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr}, nil
	}
	resolved, err := lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	addrs := make([]netip.Addr, 0, len(resolved))
	for _, item := range resolved {
		addr, ok := netip.AddrFromSlice(item.IP)
		if !ok {
			continue
		}
		addrs = append(addrs, addr.Unmap())
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("notification destination %q did not resolve to an IP", host)
	}
	return addrs, nil
}

// notificationDialControl runs on the raw socket right before connect, with
// the literal peer address; it is the last line of defence against any path
// that reaches the dialer with an unvetted address.
func notificationDialControl(_, address string, _ syscall.RawConn) error {
	if allowPrivateNotificationURLs() {
		return nil
	}
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("notification destination %q: %w", address, err)
	}
	if isBlockedNotificationAddr(addrPort.Addr()) {
		return fmt.Errorf("notification destination %q is a blocked address", address)
	}
	return nil
}

// validateNotificationAddress checks a host:port without dialing.
func validateNotificationAddress(ctx context.Context, address string) error {
	if allowPrivateNotificationURLs() {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ips, err := resolveNotificationAddrs(ctx, net.DefaultResolver.LookupIPAddr, host)
	if err != nil {
		return err
	}
	for _, ip := range ips {
		if isBlockedNotificationAddr(ip) {
			return fmt.Errorf("notification destination %q resolves to a blocked address", address)
		}
	}
	return nil
}
