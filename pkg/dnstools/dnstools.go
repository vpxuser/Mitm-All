package dnstools

import (
	"context"
	"fmt"
	"net"
	"time"
)

// DNS2IPv4 DNS查询过滤IPv4地址
func DNS2IPv4(domain, dns string) ([]string, error) {
	ips, err := DNS2IP(domain, dns)
	if err != nil {
		return nil, fmt.Errorf("DNS Query failed : %v", err)
	}
	ipv4s := make([]string, 0)
	for _, ip := range ips {
		if ip.To4() != nil {
			ipv4s = append(ipv4s, ip.String())
		}
	}
	return ipv4s, nil
}

// DNS2IP DNS查询
func DNS2IP(domain, dns string) ([]net.IP, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Second * 5,
			}
			return d.DialContext(ctx, network, dns+":53")
		},
	}
	ips, err := resolver.LookupIP(context.Background(), "ip", domain)
	if err != nil {
		return nil, fmt.Errorf("resolve %s failed : %v", domain, err)
	}
	return ips, nil
}
