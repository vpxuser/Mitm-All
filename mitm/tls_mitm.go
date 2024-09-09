package mitm

import (
	"bufio"
	"net"
	"net/http"
)

// DNS over HTTP 可能会影响中间人攻击，后续客户端连接不会传输SNI，不知道伪造证书的具体域名

type ModifyRequest func(req *http.Request, ctx *Context) (*http.Request, *http.Response)

type ModifyResponse func(resp *http.Response, ctx *Context) *http.Response

type HandleRecord func(reader *bufio.Reader, conn net.Conn, ctx *Context) error

var HandleTLSRecordPipeLine = []HandleRecord{
	ReadClientHello,
	WriteServerHello,
	WriteCertificate,
	WriteServerHelloDone,
	ReadClientKeyExchange,
	ReadChangeCipherSpec,
	ReadFinished,
	WriteChangeCipherSpec,
	WriteFinished,
	ReadApplicationData,
	WriteApplicationData,
}

func TLSMITM(reader *bufio.Reader, conn net.Conn, ctx *Context) {
	defer conn.Close()
	ctx.ModifyRequestPiPeLine = []ModifyRequest{
		DNSRequest,
		DebugRequest,
	}
	ctx.ModifyResponsePiPeLine = []ModifyResponse{
		GzipDecompressResponse,
		HTTPDNSResponse,
		GzipCompressResponse,
		DebugResponse,
	}
	for _, handler := range HandleTLSRecordPipeLine {
		if err := handler(reader, conn, ctx); err != nil {
			return
		}
	}

}
