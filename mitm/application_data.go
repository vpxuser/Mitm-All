package mitm

import (
	"bufio"
	"bytes"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
	"net/http"
	"net/http/httputil"
	"socks2https/pkg/cert"
	"socks2https/pkg/color"
	"socks2https/pkg/httptools"
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
	tamplate := fmt.Sprintf("%s [%s] [%s]", ctx.Client2MitmLog, color.SetColor(color.YELLOW_COLOR_TYPE, "Application Data"), color.SetColor(color.RED_COLOR_TYPE, "Request"))

	record, err := FilterRecord(reader, ContentTypeApplicationData, 0xff, ctx)
	if err != nil {
		return fmt.Errorf("%s %v", tamplate, err)
	}

	//yaklog.Infof("%s\n%s", tamplate, record.Fragment)

	ctx.Request, err = httptools.ReadRequest(bufio.NewReader(bytes.NewReader(record.Fragment)), "https")
	if err != nil {
		return fmt.Errorf("%s %v", tamplate, err)
	}
	//yaklog.Infof("%s read TLS Record successfully", tamplate)

	if ctx.Request.Host == "api.watch.okii.com" {
		yaklog.Debugf(color.SetColor(color.RED_COLOR_TYPE, cert.CertificateDB["api.watch.okii.com"]))
	}

	// HTTP Request 报文篡改
	for _, modifyRequest := range ctx.ModifyRequestPiPeLine {
		ctx.Request, ctx.Response = modifyRequest(ctx.Request, ctx)
	}

	//color.DumpRequest(ctx.Request, true, color.RED_COLOR_TYPE)
	return nil
})

var WriteApplicationData = HandleRecord(func(reader *bufio.Reader, conn net.Conn, ctx *Context) error {
	tamplate := fmt.Sprintf("%s [%s] [%s]", ctx.Client2MitmLog, color.SetColor(color.YELLOW_COLOR_TYPE, "Application Data"), color.SetColor(color.RED_COLOR_TYPE, "Response"))

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

	blockRecord, err = NewBlockRecord(NewAlert(AlertLevelWarning, AlertDescriptionCloseNotify, ctx), ctx)
	if err != nil {
		return fmt.Errorf("%s %v", tamplate, err)
	}
	if _, err = conn.Write(blockRecord); err != nil {
		return fmt.Errorf("%s write TLS Record failed : %v", tamplate, err)
	}

	//yaklog.Infof("%s write TLS Record successfully", tamplate)
	//yaklog.Infof("%s\n%s", tamplate, record.Fragment)
	return nil
})
