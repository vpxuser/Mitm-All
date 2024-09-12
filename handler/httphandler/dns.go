package httphandler

import (
	yaklog "github.com/yaklang/yaklang/common/log"
	"net/http"
	"socks2https/context"
	"socks2https/database"
	"socks2https/pkg/colorutils"
	"socks2https/pkg/dnsutils"
	"socks2https/services"
	"socks2https/setting"
)

var DNSRequest = RequestHandler(func(req *http.Request, ctx *context.Context) (*http.Request, *http.Response) {
	if _, err := services.GetIPByDomain(database.Cache, req.Host); err != nil {
		ipv4s, err := dnsutils.DNS2IPv4(req.Host, setting.Config.DNS)
		if err != nil {
			yaklog.Warnf(colorutils.SetColor(colorutils.MAGENTA_COLOR_TYPE, err))
			return req, nil
		}
		for _, ipv4 := range ipv4s {
			if err = services.AddIPMapping(database.Cache, ipv4, req.Host); err != nil {
				yaklog.Warnf(colorutils.SetColor(colorutils.MAGENTA_COLOR_TYPE, err))
			}
		}
	}
	return req, nil
})
