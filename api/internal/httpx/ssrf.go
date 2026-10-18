package httpx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	ErrBlockedURL       = errors.New("url targets a private, loopback, or cloud metadata address")
	ErrInvalidScheme    = errors.New("only https and http schemes are supported")
	ErrTooManyRedirects = errors.New("too many redirects during url import")
)

var blockedCIDRs = []*net.IPNet{
	mustParseCIDR("0.0.0.0/8"),          // "This host on this network"
	mustParseCIDR("10.0.0.0/8"),         // RFC 1918 Private
	mustParseCIDR("100.64.0.0/10"),      // Shared address space (CGNAT)
	mustParseCIDR("127.0.0.0/8"),        // IPv4 Loopback
	mustParseCIDR("169.254.0.0/16"),     // IPv4 Link-local / AWS/GCP/Azure Metadata
	mustParseCIDR("172.16.0.0/12"),      // RFC 1918 Private
	mustParseCIDR("192.0.0.0/24"),       // IETF Protocol Assignments
	mustParseCIDR("192.0.2.0/24"),       // Documentation (TEST-NET-1)
	mustParseCIDR("192.168.0.0/16"),     // RFC 1918 Private
	mustParseCIDR("198.18.0.0/15"),      // Benchmark testing
	mustParseCIDR("198.51.100.0/24"),    // Documentation (TEST-NET-2)
	mustParseCIDR("203.0.113.0/24"),     // Documentation (TEST-NET-3)
	mustParseCIDR("224.0.0.0/4"),        // Multicast
	mustParseCIDR("240.0.0.0/4"),        // Reserved for future use
	mustParseCIDR("255.255.255.255/32"), // Limited broadcast
	mustParseCIDR("::/128"),             // IPv6 Unspecified
	mustParseCIDR("::1/128"),            // IPv6 Loopback
	mustParseCIDR("fc00::/7"),           // IPv6 Unique Local Address
	mustParseCIDR("fe80::/10"),          // IPv6 Link-local
	mustParseCIDR("ff00::/8"),           // IPv6 Multicast
}

func mustParseCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// IsRestrictedIP checks if an IP is private, loopback, multicast, or metadata.
func IsRestrictedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	// Check IPv4-mapped IPv6 address (e.g. ::ffff:127.0.0.1)
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	for _, cidr := range blockedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// NewSSRFSafeClient creates an HTTP client with pinned safe IP dialing to prevent
// DNS rebinding and access to internal cloud metadata or intranet infrastructure.
func NewSSRFSafeClient(timeout time.Duration, allowInsecureHTTP bool) *http.Client {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		Proxy:                 nil, // Disable proxies to prevent proxy bypasses
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}

			// Resolve host and ensure ALL returned addresses are safe
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
			if err != nil {
				return nil, fmt.Errorf("resolve host %q: %w", host, err)
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("no ip addresses resolved for host %q", host)
			}

			var safeIP net.IP
			for _, ip := range ips {
				if IsRestrictedIP(ip) {
					return nil, fmt.Errorf("%w: %s resolves to restricted address %s", ErrBlockedURL, host, ip.String())
				}
				if safeIP == nil {
					safeIP = ip
				}
			}

			// Dial directly to the verified safe IP to prevent DNS rebinding
			targetAddr := net.JoinHostPort(safeIP.String(), port)
			return dialer.DialContext(ctx, network, targetAddr)
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return ErrTooManyRedirects
			}
			// Revalidate redirect scheme and host
			targetURL := req.URL
			if targetURL.Scheme != "https" && (!allowInsecureHTTP || targetURL.Scheme != "http") {
				return fmt.Errorf("%w: %s", ErrInvalidScheme, targetURL.Scheme)
			}
			host := targetURL.Hostname()
			if strings.EqualFold(host, "localhost") || strings.EqualFold(host, "metadata.google.internal") {
				return ErrBlockedURL
			}
			if ip := net.ParseIP(host); ip != nil && IsRestrictedIP(ip) {
				return ErrBlockedURL
			}
			return nil
		},
	}

	return client
}

// ValidatePublicURL performs preliminary syntax and hostname checks on a target URL.
func ValidatePublicURL(rawURL string, allowInsecureHTTP bool) (*url.URL, error) {
	u, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid url format: %w", err)
	}
	if u.Scheme != "https" && (!allowInsecureHTTP || u.Scheme != "http") {
		return nil, fmt.Errorf("%w: must be https", ErrInvalidScheme)
	}
	host := u.Hostname()
	if host == "" {
		return nil, errors.New("url missing hostname")
	}
	if strings.EqualFold(host, "localhost") ||
		strings.EqualFold(host, "metadata.google.internal") ||
		strings.HasSuffix(strings.ToLower(host), ".internal") ||
		strings.HasSuffix(strings.ToLower(host), ".local") {
		return nil, ErrBlockedURL
	}
	if ip := net.ParseIP(host); ip != nil && IsRestrictedIP(ip) {
		return nil, ErrBlockedURL
	}
	return u, nil
}
