package httphandler

import (
	"net/http"
	"socks2https/context"
)

type RequestHandler func(req *http.Request, ctx *context.Context) (*http.Request, *http.Response)

type ResponseHandler func(resp *http.Response, ctx *context.Context) *http.Response

var (
	RequestHandlers = []RequestHandler{
		DNSRequest,
		DebugRequest,
	}
	ResponseHandlers = []ResponseHandler{
		GzipDecompressResponse,
		HTTPDNSResponse,
		GzipCompressResponse,
		DebugResponse,
	}
)
