package mitm

import (
	"bufio"
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
	"net/http"
	"socks2https/pkg/httptools"
)

var HttpMethod = map[string]string{
	http.MethodGet[:3]:     http.MethodGet,
	http.MethodHead[:3]:    http.MethodHead,
	http.MethodPost[:3]:    http.MethodPost,
	http.MethodPut[:3]:     http.MethodPut,
	http.MethodPatch[:3]:   http.MethodPatch,
	http.MethodDelete[:3]:  http.MethodDelete,
	http.MethodConnect[:3]: http.MethodConnect,
	http.MethodOptions[:3]: http.MethodOptions,
	http.MethodTrace[:3]:   http.MethodTrace,
}

func HTTPMITM(reader *bufio.Reader, conn net.Conn, ctx *Context) {
	defer conn.Close()
	req, err := httptools.ReadRequest(reader, "http")
	if err != nil {
		yaklog.Errorf("%s %v", ctx.Client2MitmLog, err)
		return
	}

	ctx.ModifyRequestPiPeLine = []ModifyRequest{
		DNSRequest,
		DebugRequest,
	}

	for _, modifyRequest := range ctx.ModifyRequestPiPeLine {
		ctx.Request, ctx.Response = modifyRequest(req, ctx)
	}

	ctx.ModifyResponsePiPeLine = []ModifyResponse{
		GzipDecompressResponse,
		HTTPDNSResponse,
		GzipCompressResponse,
		DebugResponse,
	}

	if ctx.Response == nil {
		ctx.Response, err = ctx.HttpClient.Do(ctx.Request)
		if err != nil {
			yaklog.Errorf("%s Write Request Failed : %v", ctx.Mitm2ClientLog, err)
			return
		}
		for _, modifyResponse := range ctx.ModifyResponsePiPeLine {
			ctx.Response = modifyResponse(ctx.Response, ctx)
		}
	}

	if err = ctx.Response.Write(conn); err != nil {
		yaklog.Errorf("%s Write HTTP Response Failed : %v", ctx.Mitm2ClientLog, err)
		return
	}
}
