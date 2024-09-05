package dns

import (
	"context"
	"fmt"
	"net"
	"socks2https/pkg/cert"
	"time"
)

// DNStoIPv4 DNS查询过滤IPv4地址
func DNStoIPv4(domain, dns string) error {
	ips, err := DNStoIP(domain, dns, "ip")
	if err != nil {
		return err
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			cert.IPtoDomain[ip.String()] = append(cert.IPtoDomain[ip.String()], domain)
		}
	}
	return nil
}

// DNStoIP DNS查询
func DNStoIP(domain, dns, ipType string) ([]net.IP, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Second * 5,
			}
			return d.DialContext(ctx, network, dns+":53")
		},
	}
	ips, err := resolver.LookupIP(context.Background(), ipType, domain)
	if err != nil {
		return nil, fmt.Errorf("resolve %s failed : %v", domain, err)
	}
	return ips, nil
}
