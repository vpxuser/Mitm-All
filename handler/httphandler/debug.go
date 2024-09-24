package httphandler

import (
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"net/http"
	"net/http/httputil"
	"socks2https/context"
	"socks2https/pkg/colorutils"
)

var DebugRequest = RequestHandler(func(req *http.Request, ctx *context.Context) (*http.Request, *http.Response) {
	var tamplate string
	if ctx.TLSContext != nil {
		tamplate = fmt.Sprintf("%s [%s] [%s]", ctx.Client2MitmLog, colorutils.SetColor(colorutils.YELLOW_COLOR_TYPE, "HTTP"), colorutils.SetColor(colorutils.RED_COLOR_TYPE, "Request"))
	} else {
		tamplate = fmt.Sprintf("%s [%s]", ctx.Client2MitmLog, colorutils.SetColor(colorutils.RED_COLOR_TYPE, "Request"))
	}

	dump, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		yaklog.Warnf("%s Failed to Dump Request  : %v", tamplate, err)
	} else {
		yaklog.Infof("%s\n%s", tamplate, dump)
	}
	return req, nil
})

var DebugResponse = ResponseHandler(func(resp *http.Response, ctx *context.Context) *http.Response {
	var tamplate string
	if ctx.TLSContext != nil {
		tamplate = fmt.Sprintf("%s [%s] [%s]", ctx.Mitm2ClientLog, colorutils.SetColor(colorutils.YELLOW_COLOR_TYPE, "HTTP"), colorutils.SetColor(colorutils.RED_COLOR_TYPE, "Request"))
	} else {
		tamplate = fmt.Sprintf("%s [%s]", ctx.Mitm2ClientLog, colorutils.SetColor(colorutils.RED_COLOR_TYPE, "Request"))
	}
	dump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		yaklog.Warnf("%s Failed to Dump Response : %v", tamplate, err)
	} else {
		yaklog.Infof("%s\n%s", tamplate, dump)
	}
	return resp
})
