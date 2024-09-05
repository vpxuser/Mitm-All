package mitm

import (
	"bytes"
	"encoding/json"
	yaklog "github.com/yaklang/yaklang/common/log"
	"io"
	"net/http"
	"socks2https/pkg/cert"
)

type BaiduHttpDNS struct {
	Clientip string `json:"clientip"`
	Data     map[string]struct {
		IPv4 struct {
			Ip  []string `json:"ip"`
			Ttl int      `json:"ttl"`
			Msg string   `json:"msg"`
		} `json:"ipv4"`
		IPv6 struct {
			Ip  []string `json:"ip"`
			Ttl int      `json:"ttl"`
			Msg string   `json:"msg"`
		} `json:"ipv6"`
	} `json:"data"`
	Msg      string `json:"msg"`
	Serverip struct {
		Ipv4 []string `json:"ipv4"`
	} `json:"serverip"`
	Timestamp int `json:"timestamp"`
}

var HttpDNSResponse = ModifyResponse(func(resp *http.Response, ctx *Context) *http.Response {
	switch ctx.Request.Host {
	case "httpdns.baidubce.com":
		baiduDNS := &BaiduHttpDNS{}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			yaklog.Warnf("read Response Body failed : %v", err)
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))
		if err = json.Unmarshal(body, baiduDNS); err != nil {
			yaklog.Warnf("parse Response Body failed : %v", err)
		}
		for domain, ip := range baiduDNS.Data {
			_, _, err := cert.GetCertificateAndKey(cert.CertificateAndPrivateKeyPath, domain)
			if err != nil {
				yaklog.Warnf("%v", err)
			}
			for _, ipv4 := range ip.IPv4.Ip {
				cert.IPtoDomain[ipv4] = append(cert.IPtoDomain[ipv4], domain)
			}
		}
	}
	return resp
})
