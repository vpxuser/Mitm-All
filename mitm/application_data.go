package mitm

import (
	"bufio"
	"bytes"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
	"net/http"
	"net/http/httputil"
	"socks2https/pkg/comm"
)

func NewApplicationData(resp *http.Response, ctx *Context) (*Record, error) {
	fragment, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return nil, fmt.Errorf("dump Response failed : %v", err)
	}
	return &Record{
		ContentType:     ContentTypeApplicationData,
		Version:         ctx.Version,
		Length:          uint16(len(fragment)),
		Fragment:        fragment,
		ApplicationData: fragment,
	}, nil
}

var ReadApplicationData = HandleRecord(func(reader *bufio.Reader, conn net.Conn, ctx *Context) error {
	tamplate := fmt.Sprintf("%s [%s] [%s]", ctx.Client2MitmLog, comm.SetColor(comm.YELLOW_COLOR_TYPE, "Application Data"), comm.SetColor(comm.RED_COLOR_TYPE, "Request"))

	//todo 对分块的TLS记录进行处理
	record, err := FilterRecord(reader, ContentTypeApplicationData, 0xff, ctx)
	if err != nil {
		return fmt.Errorf("%s %v", tamplate, err)
	}

	ctx.Request, err = http.ReadRequest(bufio.NewReader(bytes.NewReader(record.Fragment)))
	if err != nil {
		return fmt.Errorf("%s read Request failed : %v", tamplate, err)
	}
	//yaklog.Infof("%s read TLS Record successfully", tamplate)

	// 必要设置
	ctx.Request.URL.Scheme = "https"
	ctx.Request.URL.Host = ctx.Request.Host
	ctx.Request.RequestURI = ""

	//ctx.Request.TLS = &tls.ConnectionState{
	//	Version: tls.VersionTLS13,
	//	//HandshakeComplete:  true,
	//	DidResume: false,
	//	//CipherSuite:        tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	//	ServerName:         ctx.Request.Host,
	//	NegotiatedProtocol: "http/1.1",
	//}
	//
	////ctx.Request.Header.Set("X-Forwarded-Proto", "https")
	////ctx.Request.Header.Set("Connection", "close")

	// HTTP Request 报文篡改
	for _, modifyRequest := range ctx.ModifyRequestPiPeLine {
		ctx.Request, ctx.Response = modifyRequest(ctx.Request, ctx)
	}

	//yaklog.Infof("%s\n%s", tamplate, record.Fragment)
	comm.DumpRequest(ctx.Request, true, comm.RED_COLOR_TYPE)
	return nil
})

var WriteApplicationData = HandleRecord(func(reader *bufio.Reader, conn net.Conn, ctx *Context) error {
	tamplate := fmt.Sprintf("%s [%s] [%s]", ctx.Client2MitmLog, comm.SetColor(comm.YELLOW_COLOR_TYPE, "Application Data"), comm.SetColor(comm.RED_COLOR_TYPE, "Response"))

	if ctx.Response == nil {
		resp, err := ctx.HttpClient.Do(ctx.Request)
		if err != nil {
			return fmt.Errorf("%s write Request failed : %v", tamplate, err)
		}
		ctx.Response = resp
		for _, modifyResponse := range ctx.ModifyResponsePiPeLine {
			ctx.Response = modifyResponse(ctx.Response, ctx)
		}
	}

	record, err := NewApplicationData(ctx.Response, ctx)
	if err != nil {
		return fmt.Errorf("%s %v", tamplate, err)
	}

	blockRecord, err := NewBlockRecord(record, ctx)
	if err != nil {
		return fmt.Errorf("%s %v", tamplate, err)
	}

	if _, err = conn.Write(blockRecord); err != nil {
		return fmt.Errorf("%s write TLS Record failed : %v", tamplate, err)
	}

	//yaklog.Infof("%s write TLS Record successfully", tamplate)
	yaklog.Infof("%s\n%s", tamplate, record.Fragment)
	return nil
})
