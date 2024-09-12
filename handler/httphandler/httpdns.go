package httphandler

import (
	"bytes"
	"encoding/json"
	yaklog "github.com/yaklang/yaklang/common/log"
	"io"
	"net/http"
	"socks2https/context"
	"socks2https/database"
	"socks2https/pkg/colorutils"
	"socks2https/services"
)

type BaiduHTTPDNS struct {
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

var HTTPDNSResponse = ResponseHandler(func(resp *http.Response, ctx *context.Context) *http.Response {
	switch ctx.HTTPContext.Request.Host {
	case "httpdns.baidubce.com":
		baiduDNS := &BaiduHTTPDNS{}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			yaklog.Warnf("read Response Body failed : %v", err)
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))
		if err = json.Unmarshal(body, baiduDNS); err != nil {
			yaklog.Warnf("parse Response Body failed : %v", err)
		}
		for domain, ip := range baiduDNS.Data {
			for _, ipv4 := range ip.IPv4.Ip {
				if err = services.AddIPMapping(database.Cache, ipv4, domain); err != nil {
					yaklog.Warnf(colorutils.SetColor(colorutils.MAGENTA_COLOR_TYPE, err))
					return resp
				}
			}
		}
	}
	return resp
})
