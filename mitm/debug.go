package mitm

import (
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"net/http"
	"net/http/httputil"
	"socks2https/pkg/color"
)

var DebugRequest = ModifyRequest(func(req *http.Request, ctx *Context) (*http.Request, *http.Response) {
	tamplate := fmt.Sprintf("%s [%s] [%s]", ctx.Client2MitmLog, color.SetColor(color.YELLOW_COLOR_TYPE, "Application Data"), color.SetColor(color.RED_COLOR_TYPE, "Request"))
	dump, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		yaklog.Warnf("%s dump Request failed : %v", tamplate, err)
	} else {
		yaklog.Infof("%s\n%s", tamplate, dump)
	}
	return req, nil
})

var DebugResponse = ModifyResponse(func(resp *http.Response, ctx *Context) *http.Response {
	tamplate := fmt.Sprintf("%s [%s] [%s]", ctx.Mitm2ClientLog, color.SetColor(color.YELLOW_COLOR_TYPE, "Application Data"), color.SetColor(color.RED_COLOR_TYPE, "Response"))
	dump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		yaklog.Warnf("%s dump Response failed : %v", tamplate, err)
	} else {
		yaklog.Infof("%s\n%s", tamplate, dump)
	}
	return resp
})
