package notify

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
)

func TestIsBlockedNotificationAddrRanges(t *testing.T) {
	blocked := []string{
		"0.0.0.0", "0.1.2.3", "10.1.2.3", "100.64.0.1", "100.127.255.254",
		"127.0.0.1", "169.254.169.254", "172.16.0.1", "172.31.255.255",
		"192.0.0.8", "192.0.2.10", "192.88.99.1", "192.168.1.1",
		"198.18.0.1", "198.19.255.255", "198.51.100.7", "203.0.113.9",
		"224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255",
		"::", "::1", "::127.0.0.1", "::ffff:127.0.0.1", "::ffff:10.0.0.1",
		"::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe", "64:ff9b:1::1",
		"100::1", "2001::1", "2001:db8::1", "2002:7f00:1::1", "3fff::1",
		"fc00::1", "fd12:3456::1", "fe80::1", "fec0::1", "ff02::1",
	}
	for _, value := range blocked {
		if !isBlockedNotificationAddr(netip.MustParseAddr(value)) {
			t.Errorf("expected %s to be blocked", value)
		}
	}
	allowed := []string{"93.184.216.34", "1.1.1.1", "8.8.8.8", "100.128.0.1", "198.20.0.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"}
	for _, value := range allowed {
		if isBlockedNotificationAddr(netip.MustParseAddr(value)) {
			t.Errorf("expected %s to be allowed", value)
		}
	}
	if !isBlockedNotificationAddr(netip.Addr{}) {
		t.Error("expected the zero address to be blocked")
	}
}

type recordingDial struct {
	addresses []string
}

func (r *recordingDial) dial(_ context.Context, _, address string) (net.Conn, error) {
	r.addresses = append(r.addresses, address)
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}

func TestGuardedDialResolvesOnceAndDialsVettedIP(t *testing.T) {
	t.Setenv("HIBOU_ALLOW_PRIVATE_NOTIFICATION_URLS", "false")
	var calls atomic.Int32
	// Rebinding resolver: public answer first, loopback on any later lookup.
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		if calls.Add(1) == 1 {
			return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
		}
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	rec := &recordingDial{}
	conn, err := newGuardedDial(lookup, rec.dial)(context.Background(), "tcp", "hooks.example.com:443")
	if err != nil {
		t.Fatalf("expected public destination to be allowed, got %v", err)
	}
	_ = conn.Close()
	if calls.Load() != 1 {
		t.Fatalf("expected exactly one DNS lookup, got %d", calls.Load())
	}
	if len(rec.addresses) != 1 || rec.addresses[0] != "93.184.216.34:443" {
		t.Fatalf("expected dial to the vetted IP, got %v", rec.addresses)
	}

	// A second connection sees the rebound answer and must be rejected.
	if _, err := newGuardedDial(lookup, rec.dial)(context.Background(), "tcp", "hooks.example.com:443"); err == nil {
		t.Fatal("expected rebound loopback answer to be rejected")
	}
	if len(rec.addresses) != 1 {
		t.Fatalf("expected no dial after rejection, got %v", rec.addresses)
	}
}

func TestGuardedDialRejectsMixedAnswers(t *testing.T) {
	t.Setenv("HIBOU_ALLOW_PRIVATE_NOTIFICATION_URLS", "false")
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}, {IP: net.ParseIP("100.64.1.1")}}, nil
	}
	rec := &recordingDial{}
	_, err := newGuardedDial(lookup, rec.dial)(context.Background(), "tcp", "mixed.example.com:443")
	if err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("expected mixed public/CGNAT answer to be rejected, got %v", err)
	}
	if len(rec.addresses) != 0 {
		t.Fatalf("expected no dial, got %v", rec.addresses)
	}
}

func TestGuardedDialRejectsLiteralBlockedIPs(t *testing.T) {
	t.Setenv("HIBOU_ALLOW_PRIVATE_NOTIFICATION_URLS", "false")
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		return nil, errors.New("lookup must not be called for IP literals")
	}
	rec := &recordingDial{}
	for _, address := range []string{"0.0.0.0:80", "[::]:80", "[::ffff:127.0.0.1]:80", "[64:ff9b::7f00:1]:80", "198.18.0.1:25", "240.0.0.1:80"} {
		if _, err := newGuardedDial(lookup, rec.dial)(context.Background(), "tcp", address); err == nil {
			t.Errorf("expected %s to be rejected", address)
		}
	}
	if len(rec.addresses) != 0 {
		t.Fatalf("expected no dial, got %v", rec.addresses)
	}
}

func TestGuardedDialOptOutAllowsPrivate(t *testing.T) {
	t.Setenv("HIBOU_ALLOW_PRIVATE_NOTIFICATION_URLS", "true")
	rec := &recordingDial{}
	conn, err := newGuardedDial(nil, rec.dial)(context.Background(), "tcp", "127.0.0.1:25")
	if err != nil {
		t.Fatalf("expected opt-out to allow private address, got %v", err)
	}
	_ = conn.Close()
}

func TestNotificationDialControlBlocksPeer(t *testing.T) {
	t.Setenv("HIBOU_ALLOW_PRIVATE_NOTIFICATION_URLS", "false")
	if err := notificationDialControl("tcp4", "127.0.0.1:80", nil); err == nil {
		t.Fatal("expected control hook to block loopback peer")
	}
	if err := notificationDialControl("tcp6", "[fd00::1]:80", nil); err == nil {
		t.Fatal("expected control hook to block ULA peer")
	}
	if err := notificationDialControl("tcp4", "93.184.216.34:443", nil); err != nil {
		t.Fatalf("expected control hook to allow public peer, got %v", err)
	}
}

func TestGuardedDialerRealSocketBlocksLoopbackListener(t *testing.T) {
	t.Setenv("HIBOU_ALLOW_PRIVATE_NOTIFICATION_URLS", "false")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen: %v", err)
	}
	defer listener.Close()
	dial := guardedNotificationDialContext(&net.Dialer{})
	if conn, err := dial(context.Background(), "tcp", listener.Addr().String()); err == nil {
		_ = conn.Close()
		t.Fatal("expected guarded dialer to refuse a loopback listener")
	}
}

func TestEmailSenderDoesNotFallBackToInstanceSMTP(t *testing.T) {
	sender := &EmailSender{}
	config := mustJSON(t, map[string]any{"smtp_from": "alerts@example.com", "recipients": []string{"team@example.com"}})
	err := sender.Send(context.Background(), Payload{Title: "x", Metadata: map[string]any{"integration_config": config}})
	if err == nil || !strings.Contains(err.Error(), "requires smtp_host") {
		t.Fatalf("expected missing smtp_host to be rejected, got %v", err)
	}
}

func TestEmailSenderBlocksPrivateSMTPHost(t *testing.T) {
	t.Setenv("HIBOU_ALLOW_PRIVATE_NOTIFICATION_URLS", "false")
	sender := &EmailSender{}
	for _, host := range []string{"127.0.0.1", "169.254.169.254", "10.0.0.5", "::1"} {
		config := mustJSON(t, map[string]any{"smtp_host": host, "smtp_port": 25, "smtp_from": "alerts@example.com", "recipients": []string{"team@example.com"}})
		err := sender.Send(context.Background(), Payload{Title: "x", Metadata: map[string]any{"integration_config": config}})
		if err == nil || !strings.Contains(err.Error(), "blocked") {
			t.Errorf("expected smtp_host %s to be blocked, got %v", host, err)
		}
	}
}
